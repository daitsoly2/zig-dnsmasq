'use strict';

'require ui';
'require rpc';
'require view';
'require dom';

/* 所有信息采集都由 init 脚本的 status 子命令完成 —— nobody 无需 /bin/sh 权限。
 *
 * ★ 必须用 `status`，不能用 `info`：`info` 被 rc.common 自己占了
 *   （`/etc/rc.common:125` 的 extra_command + `:149` 的 info()，定义在我们
 *   的脚本之后，会覆盖同名函数），它输出的是 procd 的实例 JSON；而
 *   `status` 会走我们定义的 status_service()，才是人类可读的完整状态。 */
var callFileExec = rpc.declare({
	object: 'file',
	method: 'exec',
	params: [ 'command', 'params' ],
	expect: { code: 0, stdout: '' }
});

function fetchInfo() {
	return callFileExec('/etc/init.d/zig-dnsmasq', [ 'status' ])
		.then(function(res) { return (res && res.stdout) ? res.stdout : _('（无输出）'); })
		.catch(function(err) { return _('查询失败: %s').format(err.message || err); });
}

return view.extend({
	load: function() {
		return fetchInfo();
	},

	render: function(text) {
		var pre = E('pre', {
			'class': 'cbi-map-descr',
			'style': 'white-space:pre-wrap;background:#2b2b2b;color:#f1f1f1;padding:12px;' +
			         'border-radius:4px;max-height:70vh;overflow:auto;font-size:12px'
		}, [ text ]);

		var refresh = E('button', {
			'class': 'btn cbi-button cbi-button-apply',
			'click': function(ev) {
				ev.preventDefault();
				this.disabled = true;
				var btn = this;
				fetchInfo().then(function(t) {
					pre.firstChild.nodeValue = t;
					btn.disabled = false;
				});
			}
		}, _('刷新'));

		return E('div', { 'class': 'cbi-map' }, [
			E('h2', { 'name': 'content' }, _('Zig DNSMasq 状态')),
			E('div', { 'class': 'cbi-section' }, [
				E('div', { 'class': 'cbi-value' }, [ refresh ]),
				E('div', { 'class': 'cbi-value-description' },
					_('运行状态、监听套接字、生效配置与最近日志。')),
				pre
			])
		]);
	},

	handleSave: null,
	handleSaveApply: null,
	handleReset: null
});
