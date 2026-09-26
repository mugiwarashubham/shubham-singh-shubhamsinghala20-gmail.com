import * as auth from './auth.js';
import * as orgs from './orgs.js';
import * as invites from './invites.js';
import * as devices from './devices.js';
import * as sessions from './sessions.js';
export function registerRoutes(router,deps){ auth.register(router,deps); orgs.register(router,deps); invites.register(router,deps); devices.register(router,deps); sessions.register(router,deps); }
