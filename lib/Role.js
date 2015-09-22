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
 * Provides the Role entity schema.
 *
 * @author Orgun109uk <orgun109uk@gmail.com>
 */

var loader = require('nsloader'),
    Schema = loader('Entity/EntityManager/Schema');

/**
 * Determine if a permission or permissions have been granted.
 *
 * @param {String|Array} permissions A permission or an array of permissions.
 * @return {Boolean} Returns true if the permission or permissions have been
 *   granted.
 *@memberof ACLRole
 */
function RoleGranted(permissions) {
  'use strict';

  if (this.get('isSuper', false) === true) {
    return true;
  }

  var perms = this.get('permissions', {}),
      granted = {},
      inherit = this.get('inherit');

  permissions = permissions instanceof Array ? permissions : [permissions];
  permissions.forEach(function (permission) {
    if (
      perms && (
        (
          perms[permission] === true
        ) || (
          perms[permission] === undefined && inherit &&
          inherit.granted(permission)
        )
      )
    ) {
      granted[permission] = true;
    }
  });

  return Object.keys(granted).length === Object.keys(permissions).length;
}

/**
 * Grant permissions to this role.
 *
 * @param {String|Array} permissions A permission or an array of permissions.
 * @param {Function} done The done callback.
 *   @param {Error} done.err Any raised errors.
 * @memberof ACLRole
 */
function RoleGrant(permissions, done) {
  'use strict';

  var perms = this.get('permissions', {});

  permissions = permissions instanceof Array ? permissions : [permissions];
  permissions.forEach(function (permission) {
    perms[permission] = true;
  });

  this.set('permissions', perms, done);
}

/**
 * Revokes permissions from this role.
 *
 * @param {String|Array} permissions A permission or an array of permissions.
 * @param {Function} done The done callback.
 *   @param {Error} done.err Any raised errors.
 * @memberof ACLRole
 */
function RoleRevoke(permissions, done) {
  'use strict';

  var perms = this.get('permissions', {});

  permissions = permissions instanceof Array ? permissions : [permissions];
  permissions.forEach(function (permission) {
    perms[permission] = false;
  });

  this.set('permissions', perms, done);
}

/**
 * Resets the provided permission or permissions.
 *
 * @param {String|Array} permissions A permission or an array of permissions.
 * @param {Function} done The done callback.
 *   @param {Error} done.err Any raised errors.
 * @memberof ACLRole
 */
function RoleReset(permissions, done) {
  'use strict';

  var perms = this.get('permissions', {});

  permissions = permissions instanceof Array ? permissions : [permissions];
  permissions.forEach(function (permission) {
    delete perms[permission];
  });

  this.set('permissions', perms, done);
}

/**
 * Defines the ACL Role entity.
 */
module.exports = function (core, done) {
  'use strict';

  core.eventManager.listen('entity[acl-role].construct', function (nxt, prms) {
    Object.defineProperties(prms.entity, {
      granted: {
        value: RoleGranted
      },
      grant: {
        value: RoleGrant
      },
      revoke: {
        value: RoleRevoke
      },
      reset: {
        value: RoleReset
      }
    });
  }, null, -100);

  var schema = new Schema(core.entityManager);

  schema.machineName = 'acl-role';
  schema.title = 'ACL Role';
  schema.description = 'The ACL Role entity which provides group permissions \
    for assigned users.';

  schema
    .addField(
      'title',
      'Title',
      'The title of the ACL role.',
      'String',
      {
        'default': ''
      }
    )
    .addFieldSanitization('title', 'trim');

  schema
    .addField(
      'description',
      'Description',
      'The description of the ACL role.',
      'String'
    )
    .addFieldSanitization('description', 'trim');

  schema
    .addField(
      'isSuper',
      'isSuper',
      'Determine if this is a super role.',
      'Boolean',
      {
        'default': false
      }
    );

  schema
    .addField(
      'permissions',
      'Permissions',
      'An object containing the available permissions.',
      'Object',
      {
        'default': {}
      }
    );

  schema
    .addField(
      'inherit',
      'Inherit',
      'Inherit permissions from a given role.',
      'Entity'
    )
    .addFieldValidation('inherit', 'entity', {
      type: 'acl-role'
    })
    .addFieldSanitization('inherit', 'entity');

  schema.save(done);
};
