'use strict';

'require form';
'require ui';
'require rpc';
'require view';
'require dom';

/* 调 init 脚本的 enable/disable —— 与状态页同一套 file.exec 通道 */
var callInitAction = rpc.declare({
	object: 'file',
	method: 'exec',
	params: [ 'command', 'params' ]
});

/* 通过 rpcd 的 file.exec 调用 init 脚本。
 * 对应 /usr/share/rpcd/acl.d/luci-app-zig-dnsmasq.json 里授予的 exec 权限。 */
var callFileExec = rpc.declare({
	object: 'file',
	method: 'exec',
	params: [ 'command', 'params' ],
	expect: { code: 0, stdout: '' }
});

function runAction(action, confirmMsg) {
	if (confirmMsg && !confirm(confirmMsg))
		return Promise.resolve(null);

	ui.showModal(_('处理中'), E('p', { 'class': 'spinning' },
		_('正在对 zig-dnsmasq 执行 %s…').format(action)));

	return callFileExec('/etc/init.d/zig-dnsmasq', [ action ])
		.then(function() {
			ui.hideModal();
			ui.addNotification(null, E('p', {},
				_('zig-dnsmasq: %s 已完成。').format(action)), 'notice');
		})
		.catch(function(err) {
			ui.hideModal();
			ui.addNotification(null, E('p', {},
				_('zig-dnsmasq: %s 失败 — %s').format(action, err.message || err)), 'error');
		});
}

return view.extend({
	render: function() {
		var m, s, o;

		m = new form.Map('zig-dnsmasq', _('Zig DNSMasq'),
			_('基于 Zig 0.16 移植的 dnsmasq 2.93，带异步转发引擎。本服务独立于系统 dnsmasq；使用下方「接管 53 端口」操作可让它替换系统解析器。'));

		s = m.section(form.NamedSection, 'main', 'zig-dnsmasq', _('常规设置'));

		o = s.option(form.Flag, 'enabled', _('启用'),
			_('以 procd 服务方式运行 zig-dnsmasq，并创建 /etc/rc.d 自启链接（重启后自动运行）。'));
		o.rmempty = false;
		// 这个开关必须同时驱动 init 的 enable/disable。
		//
		// 原因：UCI 里的 `option enabled '1'` **只**让 start_service 继续往下走，
		// 它**不会**创建 /etc/rc.d/S60zig-dnsmasq。光设它，重启后服务根本不会
		// 被调用到，自然不会起来 —— 真实故障就是这样发生的（路由器重启后
		// zig-dnsmasq 没启动，而 enabled 早就是 1、自启链接却缺失）。
		// 之前这个页面只有 Flag、从不调 enable，等于把「启用」做成了半个开关。
		o.write = function(section_id, value) {
			var self = this;
			var action = (value == '1' || value === true) ? 'enable' : 'disable';
			return self.super('write', [ section_id, value ]).then(function(rv) {
				return L.resolveDefault(callInitAction('/etc/init.d/zig-dnsmasq', [ action ]), null)
					.then(function() { return rv; });
			});
		};

		o = s.option(form.Value, 'port', _('监听端口'),
			_('DNS 监听端口。修改后需重启服务才会生效。'));
		o.datatype = 'port';
		o.default = 53;
		o.rmempty = false;

		o = s.option(form.Value, 'interfaces', _('监听接口'),
			_('以空格分隔的接口名，例如 br-lan。留空则监听所有地址（路由器上不推荐——会把解析器暴露到 WAN）。'));
		o = s.option(form.Value, 'except_interfaces', _('排除接口'),
			_('永不监听的接口。'));

		s = m.section(form.NamedSection, 'main', 'zig-dnsmasq', _('上游服务器'));

		o = s.option(form.Flag, 'noresolv', _('忽略 resolv-file'),
			_('不从 resolv 文件读取上游服务器。'));
		o = s.option(form.Value, 'resolvfile', _('resolv 文件'),
			_('上游 DNS 服务器列表文件路径。'));
		o.depends('noresolv', '0');

		o = s.option(form.DynamicList, 'server', _('静态上游服务器'),
			_('追加在 resolv 文件上游之后的额外上游服务器。'));
		o.datatype = 'ipaddr';

		o = s.option(form.Flag, 'allservers', _('并发查询所有服务器'),
			_('并行向所有上游发送查询，采用最先返回的结果。'));
		o = s.option(form.Flag, 'strictorder', _('严格顺序'),
			_('严格按配置顺序依次查询上游，而不是并发竞速。'));

		s = m.section(form.NamedSection, 'main', 'zig-dnsmasq', _('缓存'));

		o = s.option(form.Value, 'cachesize', _('缓存大小'),
			_('缓存的 DNS 记录条数。'));
		o.datatype = 'uinteger';
		o.default = 8000;

		o = s.option(form.Value, 'dnsforwardmax', _('最大并发转发数'));
		o.datatype = 'uinteger';
		o.default = 1500;

		o = s.option(form.Flag, 'negcache', _('负缓存'),
			_('缓存 NXDOMAIN / NODATA 应答。'));
		o.default = '1';

		o = s.option(form.Value, 'mincachettl', _('最小缓存 TTL'),
			_('将过短的上游 TTL 延长到该秒数（0 = 禁用）。'));
		o.datatype = 'uinteger';
		o.default = 0;

		o = s.option(form.Value, 'usestalecache', _('过期缓存续用'),
			_('记录过期后，在刷新完成前继续返回旧记录的秒数（0 = 禁用）。'));
		o.datatype = 'uinteger';
		o.default = 0;

		s = m.section(form.NamedSection, 'main', 'zig-dnsmasq', _('本地域'));

		o = s.option(form.Value, 'domain', _('本地域名'),
			_('附加到裸主机名后的域名。'));
		o = s.option(form.Value, 'local', _('权威区域'),
			_('该域名的应答仅在本地提供，不转发。'));
		o = s.option(form.Flag, 'expandhosts', _('扩展 hosts'),
			_('用本地域扩展 /etc/hosts 中的主机名。'));
		o = s.option(form.Flag, 'domainneeded', _('需要完整域名'),
			_('从不转发不带域名的裸主机名。'));
		o = s.option(form.Flag, 'boguspriv', _('阻止私网反查'),
			_('不转发私网 IP 段的反向查询。'));
		o = s.option(form.Flag, 'localise', _('按接口本地化'),
			_('根据查询到达的接口选择应答地址。'));

		s = m.section(form.NamedSection, 'main', 'zig-dnsmasq', _('高级'));

		o = s.option(form.Value, 'threads', _('工作线程数'),
			_('0 = 每 CPU 核一个。'));
		o.datatype = 'uinteger';
		o.default = 0;

		o = s.option(form.Value, 'ednsmax', _('EDNS 包大小'));
		o.datatype = 'uinteger';
		o.default = 1232;

		o = s.option(form.Flag, 'logqueries', _('记录查询日志'),
			_('记录每条查询。繁忙网络下日志量非常大。'));
		o = s.option(form.Value, 'logfacility', _('日志设施'),
			_('留空则记录到 stderr（可用 logread 查看）。'));

		return Promise.resolve(m.render()).then(function(node) {
			var bar = E('div', { 'class': 'cbi-section' }, [
				E('h3', {}, _('服务控制')),
				E('div', { 'class': 'cbi-value' }, [
					E('button', {
						'class': 'btn cbi-button cbi-button-apply',
						'style': 'margin-right:6px',
						'click': function(ev) { ev.preventDefault(); runAction('restart'); }
					}, _('重启')),
					E('button', {
						'class': 'btn cbi-button',
						'style': 'margin-right:6px',
						'click': function(ev) { ev.preventDefault(); runAction('start'); }
					}, _('启动')),
					E('button', {
						'class': 'btn cbi-button',
						'style': 'margin-right:6px',
						'click': function(ev) { ev.preventDefault(); runAction('stop'); }
					}, _('停止')),
					E('button', {
						'class': 'btn cbi-button cbi-button-positive',
						'style': 'margin-right:6px',
						'click': function(ev) {
							ev.preventDefault();
							runAction('takeover',
								_('确定接管 53 端口？\n\n' +
								  '这将停止系统 dnsmasq。本网络的 DNS 将由 zig-dnsmasq 接管，' +
								  '直到你执行「还原系统 dnsmasq」或重启路由器。'))
								.then(function() { location.reload(); });
						}
					}, _('接管 53 端口')),
					E('button', {
						'class': 'btn cbi-button cbi-button-negative',
						'click': function(ev) {
							ev.preventDefault();
							runAction('revert',
								_('确定恢复系统 dnsmasq？\n\n' +
								  'zig-dnsmasq 将被停止并禁用。'))
								.then(function() { location.reload(); });
						}
					}, _('还原系统 dnsmasq'))
				]),
				E('div', { 'class': 'cbi-value-description' },
					_('修改选项后请先「保存并应用」，再点「重启」才会生效。'))
			]);
			node.appendChild(bar);
			return node;
		});
	}
});
