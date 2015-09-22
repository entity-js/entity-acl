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
    loader = require('nsloader');

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

  // @todo - config - defaults - roles
  // @todo - config - defaults - users

  async.series(queue, done);
};
