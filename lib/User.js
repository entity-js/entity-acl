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
 * Provides the User entity schema.
 *
 * @author Orgun109uk <orgun109uk@gmail.com>
 */

var loader = require('nsloader'),
    Schema = loader('Entity/EntityManager/Schema'),
    Entity = loader('Entity/EntityManager/Entity');

/**
 * Determine if a role has been granted.
 *
 * @param {String|ACLRole} role A role or role name to check.
 * @return {Boolean} Returns true if the role has been granted.
 *@memberof ACLUser
 */
function UserGranted(role) {
  'use strict';

  var roles = this.get('roles', {}),
      name = role instanceof Entity ? role.machineName : role;

  return roles[name] !== undefined && roles[name] instanceof Entity;
}

/**
 * Grant a role to this user.
 *
 * @param {String|ACLRole} role The role to assign to this user.
 * @param {Function} done The done callback.
 *   @param {Error} done.err Any raised errors.
 * @memberof ACLUser
 */
function UserGrant(role, done) {
  'use strict';

  var roles = this.get('roles', {}),
      name = role instanceof Entity ? role.machineName : role;

  if (roles[name] !== undefined) {
    return done(null);
  }

  roles[name] = role instanceof Entity ? role : {
    type: 'acl-role',
    machineName: name
  };

  this.set('roles', roles, done);
}

/**
 * Revokes a role from this user.
 *
 * @param {String|ACLRole} role The role to remove from this user.
 * @param {Function} done The done callback.
 *   @param {Error} done.err Any raised errors.
 * @memberof ACLUser
 */
function UserRevoke(role, done) {
  'use strict';

  var roles = this.get('roles', {}),
      name = role instanceof Entity ? role.machineName : role;

  delete roles[name];
  this.set('roles', roles, done);
}

/**
 * Determine if a permission or permissions have been granted.
 *
 * @param {String|Array} permissions A permission or an array of permissions.
 * @return {Boolean} Returns true if the permission or permissions have been
 *   granted.
 *@memberof ACLUser
 */
function UserAccess(permissions) {
  'use strict';

  var roles = this.get('roles', {}),
      granted = {};

  permissions = permissions instanceof Array ? permissions : [permissions];
  permissions.forEach(function (permission) {
    for (var name in roles) {
      if (
        granted[permission] !== true &&
        roles[name] instanceof Entity &&
        roles[name].type() === 'acl-role' &&
        roles[name].granted(permission)
      ) {
        granted[permission] = true;
      }
    }
  });

  for (var i = 0, len = permissions.length; i < len; i++) {
    if (granted[permissions[i]] !== true) {
      return false;
    }
  }

  return true;
}

/**
 * Determines if the provided password matches the users stored password.
 *
 * @param {String} password The password to validate.
 * @return {Boolean} Returns true if the password matches.
 * @memberof ACLUser
 */
function UserPasswordMatch(password) {
  'use strict';

  var passwordHash = new (require('phpass').PasswordHash)();
  return passwordHash.checkPassword(password, this.get('password'));
}

/**
 * Defines the ACL Role entity.
 */
module.exports = function (core, done) {
  'use strict';

  core.eventManager.listen('entity[acl-user].construct', function (nxt, prms) {
    Object.defineProperties(prms.entity, {
      granted: {
        value: UserGranted
      },
      grant: {
        value: UserGrant
      },
      revoke: {
        value: UserRevoke
      },
      access: {
        value: UserAccess
      },
      passwordMatch: {
        value: UserPasswordMatch
      }
    });
  }, null, -100);

  var schema = new Schema(core.entityManager);

  schema.machineName = 'acl-user';
  schema.title = 'ACL User';
  schema.description = 'The ACL User entity which provides a user account.';

  schema
    .addField(
      'email',
      'Email',
      'The users email address, used to login and send emails.',
      'String',
      {
        'required': true,
        'default': ''
      }
    )
    .addFieldValidation('email', 'email')
    .addFieldSanitization('email', 'trim');

  schema
    .addField(
      'displayName',
      'Display Name',
      'The name the user wishes to use for display purposes.',
      'String'
    )
    .addFieldSanitization('displayName', 'trim');

  schema
    .addField(
      'password',
      'Password',
      'The users password.',
      'String',
      {
        'required': true,
        'default': false
      }
    )
    .addFieldValidation('password', 'password')
    .addFieldSanitization('password', 'trim')
    .addFieldSanitization('password', 'password');

  schema
    .addField(
      'roles',
      'Roles',
      'An object containing the granted roles.',
      'Entities',
      {
        'default': {}
      }
    )
    .addFieldValidation('roles', 'entities', {
      type: 'acl-role'
    })
    .addFieldSanitization('roles', 'entities');

  schema.save(done);
};
