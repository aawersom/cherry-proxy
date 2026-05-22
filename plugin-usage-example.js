/**
 * Cherry plugin — proxy integration pattern
 *
 * Store the proxy base URL in Lampa.Storage so the user can configure it
 * in the plugin settings panel without editing code.
 *
 * Usage in any Cherry component:
 *   var url = cherryProxy('https://some-adult-site.com/api/list?page=1');
 *   network.silent(url, onSuccess, onError);
 */

var PROXY_DEFAULT = 'https://cherry-proxy.YOUR-SUBDOMAIN.workers.dev/proxy';

function cherryProxyUrl() {
  return Lampa.Storage.get('cherry_proxy_url', PROXY_DEFAULT);
}

/**
 * Wraps a target URL for routing through the CORS proxy.
 * @param {string} targetUrl - Absolute URL of the upstream resource
 * @returns {string} - Proxied URL ready for Lampa.Reguest
 */
function cherryProxy(targetUrl) {
  var base  = cherryProxyUrl();
  var key   = Lampa.Storage.get('cherry_proxy_key', '');
  var built = base + '?url=' + encodeURIComponent(targetUrl);
  if (key) built += '&key=' + encodeURIComponent(key);
  return built;
}

// Settings registration (call this inside startPlugin())
function registerProxySettings() {
  Lampa.Settings.addParam({
    component: 'cherry',
    param: {
      name:    'cherry_proxy_url',
      type:    'input',
      default: PROXY_DEFAULT,
    },
    field: { name: 'Proxy URL' },
  });

  Lampa.Settings.addParam({
    component: 'cherry',
    param: {
      name:    'cherry_proxy_key',
      type:    'input',
      default: '',
    },
    field: { name: 'Proxy secret key (optional)' },
  });
}
