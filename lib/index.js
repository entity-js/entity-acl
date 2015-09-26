/**
 *  ____            __        __
 * /\  _`\         /\ \__  __/\ \__
 * \ \ \L\_\    ___\ \ ,_\/\_\ \ ,_\  __  __
 *  \ \  _\L  /' _ `\ \ \/\/\ \ \ \/ /\ \/\ \
 *   \ \ \L\ \/\ \/\ \ \ \_\ \ \ \ \_\ \ \_\ \
 *    \ \____/\ \_\ \_\ \__\\ \_\ \__\\/`____ \
 *     \/___/  \/_/\/_/\/__/ \/_/\/__/ `/___/> \
 *                                        /\___/
 *                                        \/__/
 *
 * Entity ACL
 */

/**
 * Provides the entity core callback to define the ACL.
 *
 * @author Orgun109uk <orgun109uk@gmail.com>
 */

var async = require('async'),
    Session = require('express-session'),
    MongoStore = require('connect-mongo')(Session),
    passport = require('passport'),
    loader = require('nsloader');

var sessionSecret, session;

/**
 * Event callback for the 'web.pre-init' event.
 *
 * @param {EntityCore} core The entity core object.
 * @return {Function} The event callback.
 * @private
 */
function _onWebPreInit(core) {
  'use strict';

  return function (next, args) {
    // Express MongoDB session storage.
    core.web.express.use(session({
      saveUninitialized: true,
      resave: true,
      secret: sessionSecret,
      store: session
    }));

    // Use passport session.
    core.web.express.use(passport.initialize());
    core.web.express.use(passport.session());

    next();
  };
}

/**
 * Called when the passport authorization is successful.
 *
 * @param {EntityCore} core The entity core object.
 * @return {Function} The callback.
 * @private
 */
function _onAuthorizeSuccess(core) {
  'use strict';

  return function (data, accept) {
    // @todo - access control?

    accept(null, true);
  };
}

/**
 * Called when the passport authorization fails.
 *
 * @param {EntityCore} core The entity core object.
 * @return {Function} The callback.
 * @private
 */
function _onAuthorizeFail(core) {
  'use strict';

  return function (data, msg, err, accept) {
    if (err) {
      throw new Error(msg);
    }

    // @todo - access control?

    accept(null, false);
  };
}

/**
 * Event callback for the 'web.socket.pre-init' event.
 *
 * @param {EntityCore} core The entity core object.
 * @return {Function} The event callback.
 * @private
 */
function _onWebSocketPreInit(core) {
  'use strict';

  return function (next, args) {
    args.socket.use(require('passport.socketio').authorize({
      cookieParser: require('cookie-parser'),
      key: 'session_id',
      secret: sessionSecret,
      store: session,
      success: _onAuthorizeSuccess(core),
      fail: _onAuthorizeFail(core)
    }));

    next();
  };
}

/**
 * Defines and initializes the ACL library.
 *
 * @param {EntityCore} core The entity core object.
 * @param {Object} config The ACL config object.
 * @param {Function} done The done callback.
 *   @param {Error} done.err Any raised errors.
 */
module.exports = function (core, config, done) {
  'use strict';

  if (core.sanitizers.registered('password') === false) {
    core.sanitizers.register(
      'password',
      loader('EntityACL/Sanitizers/Rules/Password')
    );
  }

  var queue = [];

  queue.push(function (next) {
    loader('EntityACL/Role')(core, next);
  });

  queue.push(function (next) {
    loader('EntityACL/User')(core, next);
  });

  if (core.web) {
    // Do this to trick connect-mongo into thinking its a native DB.
    core.database.connection().database.listCollections = true;

    sessionSecret = core.config.get('session.secret', 'entity-core');
    session = new MongoStore({
      db: core.database.connection().database
    });

    core.on('web.socket.pre-init', _onWebSocketPreInit(core));
    core.on('web.pre-init', _onWebPreInit(core));

    Object.defineProperties(this, {
      /**
       * The mongo Session store.
       *
       * @var {MongoStore} _session
       * @memberof EntityCore
       * @readOnly
       * @instance
       */
      session: {
        get: function () {
          return session;
        }
      },
      /**
       * The session secret.
       *
       * @var {String} sessionSecret
       * @memberof EntityCore
       * @readOnly
       * @instance
       */
      sessionSecret: {
        get: function () {
          return sessionSecret;
        }
      }
    });
  }

  // @todo - config - defaults - roles
  // @todo - config - defaults - users

  async.series(queue, done);
};
