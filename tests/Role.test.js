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

require('entity-core');

var test = require('unit.js'),
    async = require('async'),
    loader = require('nsloader'),
    Database = loader('Entity/Database'),
    Validators = loader('Entity/Validators'),
    Sanitizers = loader('Entity/Sanitizers'),
    EventManager = loader('Entity/EventManager'),
    EntityManager = loader('Entity/EntityManager'),
    Entity = loader('Entity/EntityManager/Entity');

var core;

describe('entityACL/Role', function () {

  'use strict';

  beforeEach(function () {

    core = {};

    core.eventManager = new EventManager(core);
    core.database = new Database(core);
    core.validators = new Validators(core);
    core.sanitizers = new Sanitizers(core);
    core.entityManager = new EntityManager(core);

    core.database.connect('test', {
      name: 'test',
      host: '0.0.0.0'
    }, true);

  });

  afterEach(function (done) {

    var queue = [];

    queue.push(function (next) {
      core.database.collection('schemas', 'test').drop(function () {
        next();
      });
    });

    queue.push(function (next) {
      core.database.collection('entity-acl-role', 'test').drop(function () {
        next();
      });
    });

    async.series(queue, function (err) {
      if (err) {
        return done(err);
      }

      core.database.disconnect('test');
      done();
    });

  });

  describe('Role()', function () {

    it('shouldBeRegistered', function (done) {

      var queue = [];

      queue.push(function (next) {

        core.entityManager.schemas(function (err, schemas) {

          if (err) {
            return next(err);
          }

          test.array(
            schemas
          ).hasLength(0);

          next();

        });

      });

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.schemas(function (err, schemas) {

          if (err) {
            return next(err);
          }

          test.array(
            schemas
          ).hasLength(1).is([{
            machineName: 'acl-role',
            title: 'ACL Role',
            description: 'The ACL Role entity which provides group permissions \
    for assigned users.'
          }]);

          next();

        });

      });

      async.series(queue, done);

    });

    it('shouldHaveMethods', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          test.object(entity)
            .isInstanceOf(Entity)
            .hasKey('granted')
            .hasKey('grant')
            .hasKey('revoke')
            .hasKey('reset');

          test.bool(
            entity.get('isSuper')
          ).isNotTrue();

          next();

        }, 'acl-role');

      });

      async.series(queue, done);

    });

  });

  describe('Role.grant()', function () {

    it('shouldGrantPermission', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          test.object(
            entity.get('permissions')
          ).notHasKey('test permission');

          entity.grant('test permission');

          test.object(
            entity.get('permissions')
          ).hasKey('test permission');

          test.bool(
            entity.get('permissions')['test permission']
          ).isTrue();

          next();

        }, 'acl-role');

      });

      async.series(queue, done);

    });

  });

  describe('Role.revoke()', function () {

    it('shouldRevokePermission', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          test.object(
            entity.get('permissions')
          ).notHasKey('test permission');

          entity.revoke('test permission');

          test.object(
            entity.get('permissions')
          ).hasKey('test permission');

          test.bool(
            entity.get('permissions')['test permission']
          ).isNotTrue();

          next();

        }, 'acl-role');

      });

      async.series(queue, done);

    });

    it('shouldRevokeGrantedPermission', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          test.object(
            entity.get('permissions')
          ).notHasKey('test permission');

          entity.grant('test permission');

          entity.revoke('test permission');

          test.object(
            entity.get('permissions')
          ).hasKey('test permission');

          test.bool(
            entity.get('permissions')['test permission']
          ).isNotTrue();

          next();

        }, 'acl-role');

      });

      async.series(queue, done);

    });

  });

  describe('Role.granted()', function () {

    it('shouldReturnFalseIfPermissionHasntBeenDefined', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          test.bool(
            entity.granted('test permission')
          ).isNotTrue();

          next();

        }, 'acl-role');

      });

      async.series(queue, done);

    });

    it('shouldReturnFalseIfPermissionIsRevoked', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.revoke('test permission');

          test.bool(
            entity.granted('test permission')
          ).isNotTrue();

          next();

        }, 'acl-role');

      });

      async.series(queue, done);

    });

    it('shouldReturnTrueIfPermissionIsGranted', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.grant('test permission');

          test.bool(
            entity.granted('test permission')
          ).isTrue();

          next();

        }, 'acl-role');

      });

      async.series(queue, done);

    });

    it('shouldReturnTrueIfSuperAndPermissionHasntBeenDefined', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.set('isSuper', true);

          test.bool(
            entity.granted('test permission')
          ).isTrue();

          next();

        }, 'acl-role');

      });

      async.series(queue, done);

    });

    it('shouldReturnTrueIfSuperAndPermissionIsRevoked', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.set('isSuper', true);
          entity.revoke('test permission');

          test.bool(
            entity.granted('test permission')
          ).isTrue();

          next();

        }, 'acl-role');

      });

      async.series(queue, done);

    });

    it('shouldReturnTrueIfAllPermissionsHaveBeenGranted', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          var q2 = [];

          q2.push(function (nxt) {

            entity.grant('test permission', nxt);

          });

          q2.push(function (nxt) {

            entity.grant('test permission 2', nxt);

          });

          q2.push(function (nxt) {

            entity.grant('test permission 3', nxt);

          });

          q2.push(function (nxt) {

            test.bool(
              entity.granted([
                'test permission', 'test permission 2', 'test permission 3'
              ])
            ).isTrue();

            nxt();

          });

          async.series(q2, next);

        }, 'acl-role');

      });

      async.series(queue, done);

    });

    it('shouldReturnFalseIfNotAllPermissionsHaveBeenGranted', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          var q2 = [];

          q2.push(function (nxt) {

            entity.grant('test permission', nxt);

          });

          q2.push(function (nxt) {

            entity.grant('test permission 2', nxt);

          });

          q2.push(function (nxt) {

            test.bool(
              entity.granted([
                'test permission', 'test permission 2', 'test permission 3'
              ])
            ).isNotTrue();

            nxt();

          });

          async.series(q2, next);

        }, 'acl-role');

      });

      async.series(queue, done);

    });

    it('shouldReturnTrueIfPermissionIsInherited', function (done) {

      var queue = [],
          inheritRole;

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          var q2 = [];

          q2.push(function (nxt) {

            entity.grant('test permission', nxt);

          });

          q2.push(function (nxt) {

            inheritRole = entity;

            nxt();

          });

          async.series(q2, next);

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          var q2 = [];

          q2.push(function (nxt) {

            entity.set('inherit', inheritRole, nxt);

          });

          q2.push(function (nxt) {

            entity.grant('test permission 2', nxt);

          });

          q2.push(function (nxt) {

            test.bool(
              entity.granted([
                'test permission', 'test permission 2'
              ])
            ).isTrue();

            nxt();

          });

          async.series(q2, next);

        }, 'acl-role');

      });

      async.series(queue, done);

    });

  });

  describe('Role.reset()', function () {

    it('shouldResetGrantedPermission', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.grant('test permission');
          entity.reset('test permission');

          test.object(
            entity.get('permissions')
          ).notHasKey('test permission');

          next();

        }, 'acl-role');

      });

      async.series(queue, done);

    });

    it('shouldResetRevokedPermission', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.revoke('test permission');
          entity.reset('test permission');

          test.object(
            entity.get('permissions')
          ).notHasKey('test permission');

          next();

        }, 'acl-role');

      });

      async.series(queue, done);

    });

  });

  describe('Role.save()', function () {

    it('shouldSaveTheEntity', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test-role-1';

          var q2 = [];

          q2.push(function (nxt) {

            entity.set('title', 'Test role #1', nxt);

          });

          q2.push(function (nxt) {

            entity.set('description', 'This is the first test role.', nxt);

          });

          q2.push(function (nxt) {

            entity.grant('test permission', nxt);

          });

          q2.push(function (nxt) {

            entity.save(nxt);

          });

          async.series(q2, next);

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test-role-2';

          var q2 = [];

          q2.push(function (nxt) {

            entity.set('title', 'Test role #2', nxt);

          });

          q2.push(function (nxt) {

            entity.set('description', 'This is the second test role.', nxt);

          });

          q2.push(function (nxt) {

            entity.set('isSuper', true, nxt);

          });

          q2.push(function (nxt) {

            entity.save(nxt);

          });

          async.series(q2, next);

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test-role-3';

          var q2 = [];

          q2.push(function (nxt) {

            entity.set('title', 'Test role #3', nxt);

          });

          q2.push(function (nxt) {

            entity.set('description', 'This is the third test role.', nxt);

          });

          q2.push(function (nxt) {

            entity.revoke('test permission', nxt);

          });

          q2.push(function (nxt) {

            entity.save(nxt);

          });

          async.series(q2, next);

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.schema('acl-role', function (err, schema) {

          if (err) {
            return next(err);
          }

          schema.entityCollection.find(function (err, docs) {

            if (err) {
              return next(err);
            }

            test.array(
              docs
            ).hasLength(3);

            test.object(docs[0])
              .hasKey('machineName', 'test-role-1')
              .hasKey('type', 'acl-role')
              .hasKey('fieldData');

            test.object(docs[0].fieldData)
              .notHasKey('isSuper')
              .hasKey('permissions');

            test.object(docs[0].fieldData.permissions)
              .hasKey('test permission', true);

            test.object(docs[1])
              .hasKey('machineName', 'test-role-2')
              .hasKey('type', 'acl-role')
              .hasKey('fieldData');

            test.object(docs[1].fieldData)
              .hasKey('isSuper', true)
              .notHasKey('permissions');

            test.object(docs[2])
              .hasKey('machineName', 'test-role-3')
              .hasKey('type', 'acl-role')
              .hasKey('fieldData');

            test.object(docs[2].fieldData)
              .notHasKey('isSuper')
              .hasKey('permissions');

            test.object(docs[2].fieldData.permissions)
              .hasKey('test permission', false);

            next();

          });

        });

      });

      async.series(queue, done);

    });

  });

  describe('Role.load()', function () {

    it('shouldLoadTheEntity', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/Role')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test-role-1';

          var q2 = [];

          q2.push(function (nxt) {

            entity.set('title', 'Test role #1', nxt);

          });

          q2.push(function (nxt) {

            entity.set('description', 'This is the first test role.', nxt);

          });

          q2.push(function (nxt) {

            entity.grant('test permission', nxt);

          });

          q2.push(function (nxt) {

            entity.save(nxt);

          });

          async.series(q2, next);

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test-role-2';

          var q2 = [];

          q2.push(function (nxt) {

            entity.set('title', 'Test role #2', nxt);

          });

          q2.push(function (nxt) {

            entity.set('description', 'This is the second test role.', nxt);

          });

          q2.push(function (nxt) {

            entity.set('isSuper', true, nxt);

          });

          q2.push(function (nxt) {

            entity.save(nxt);

          });

          async.series(q2, next);

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test-role-3';

          var q2 = [];

          q2.push(function (nxt) {

            entity.set('title', 'Test role #3', nxt);

          });

          q2.push(function (nxt) {

            entity.set('description', 'This is the third test role.', nxt);

          });

          q2.push(function (nxt) {

            entity.revoke('test permission', nxt);

          });

          q2.push(function (nxt) {

            entity.save(nxt);

          });

          async.series(q2, next);

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.load(
          'acl-role',
          'test-role-1',
          function (err, entity) {

            if (err) {
              return next(err);
            }

            test.bool(
              entity.get('isSuper')
            ).isNotTrue();

            test.bool(
              entity.granted('test permission')
            ).isTrue();

            next();

          }
        );

      });

      queue.push(function (next) {

        core.entityManager.load(
          'acl-role',
          'test-role-2',
          function (err, entity) {

            if (err) {
              return next(err);
            }

            test.bool(
              entity.get('isSuper')
            ).isTrue();

            next();

          }
        );

      });

      queue.push(function (next) {

        core.entityManager.load(
          'acl-role',
          'test-role-3',
          function (err, entity) {

            if (err) {
              return next(err);
            }

            test.bool(
              entity.get('isSuper')
            ).isNotTrue();

            test.bool(
              entity.granted('test permission')
            ).isNotTrue();

            next();

          }
        );

      });

      async.series(queue, done);

    });

  });

});
