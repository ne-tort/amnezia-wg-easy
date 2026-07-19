'use strict';

/**
 * Backward-compatible facade — prefer require('./portPlan').
 */

const portPlan = require('./portPlan');

module.exports = {
  NGINX_CONTAINER: portPlan.NGINX_CONTAINER,
  DEMUX_PUBLIC_PORT: 443,
  getDemuxPublicPort: () => 443,
  syncStreamDemux: portPlan.applyPlan,
  resolveNginxNetwork: portPlan.resolveNginxNetwork,
  assertDemuxPortAvailable: async () => {
    await portPlan.assertHostPortsAvailable([443], { allowNginx: true });
  },
  isHostTcpPortInUse: portPlan.isHostTcpPortInUse,
  mapHostPath: () => require('node:path').join(
    require('../config').WG_PATH,
    'nginx',
    'stream-sni.map',
  ),
  writeStreamMap: () => {},
  collectRoutesFromSettings: () => [],
};
