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

describe('entityACL/User', function () {

  'use strict';

  beforeEach(function (next) {

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

    core.sanitizers.register(
      'password',
      loader('EntityACL/Sanitizers/Rules/Password')
    );

    loader('EntityACL/Role')(core, next);

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

    queue.push(function (next) {
      core.database.collection('entity-acl-user', 'test').drop(function () {
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

  describe('User()', function () {

    it('shouldBeRegistered', function (done) {

      var queue = [];

      queue.push(function (next) {

        core.entityManager.schemas(function (err, schemas) {

          if (err) {
            return next(err);
          }

          test.array(
            schemas
          ).hasLength(1);

          next();

        });

      });

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.schemas(function (err, schemas) {

          if (err) {
            return next(err);
          }

          test.array(
            schemas
          ).hasLength(2).is([{
            machineName: 'acl-role',
            title: 'ACL Role',
            description: 'The ACL Role entity which provides group permissions \
    for assigned users.'
          }, {
            machineName: 'acl-user',
            title: 'ACL User',
            description: 'The ACL User entity which provides a user account.'
          }]);

          next();

        });

      });

      async.series(queue, done);

    });

    it('shouldHaveMethods', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

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
            .hasKey('passwordMatch');

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

  });

  describe('User.grant()', function () {

    it('shouldGrantTheRole', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          test.object(
            entity.get('roles')
          ).is({});

          entity.grant('test');

          test.object(
            entity.get('roles')
          ).is({
            'test': {
              type: 'acl-role',
              machineName: 'test'
            }
          });

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

  });

  describe('User.revoke()', function () {

    it('shouldRevokeTheRole', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.grant('test');
          entity.revoke('test');

          test.object(
            entity.get('roles')
          ).is({});

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

  });

  describe('User.granted()', function () {

    it('shouldReturnFalseIfNotGranted', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          test.bool(
            entity.granted('test')
          ).isNotTrue();

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

    it('shouldReturnFalseIfGrantedButAsString', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.grant('test');

          test.bool(
            entity.granted('test')
          ).isNotTrue();

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

    it('shouldReturnTrueIfGrantedAsRole', function (done) {

      var queue = [],
          role;

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test';
          role = entity;

          next();

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.grant(role);

          test.bool(
            entity.granted('test')
          ).isTrue();

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

    it('shouldReturnFalseIfRevokedRole', function (done) {

      var queue = [],
          role;

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test';
          role = entity;

          next();

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.grant(role);
          entity.revoke(role);

          test.bool(
            entity.granted('test')
          ).isNotTrue();

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

  });

  describe('User.access()', function () {

    it('shouldReturnFalseIfNoRoles', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          test.bool(
            entity.access('test permission')
          ).isNotTrue();

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

    it('shouldReturnFalseIfNotAllowed', function (done) {

      var queue = [],
          role;

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test';
          role = entity;

          next();

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.grant(role);

          test.bool(
            entity.access('test perimssion')
          ).isNotTrue();

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

    it('shouldReturnTrueIfSuper', function (done) {

      var queue = [],
          role;

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test';
          entity.set('isSuper', true);
          role = entity;

          next();

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.grant(role);

          test.bool(
            entity.access('test perimssion')
          ).isTrue();

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

    it('shouldReturnTrueIfAllowed', function (done) {

      var queue = [],
          role;

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          role = entity;
          role.machineName = 'test';
          role.grant('test permission');

          next();

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.grant(role);

          test.bool(
            entity.access('test permission')
          ).isTrue();

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

    it('shouldReturnTrueWithMultiplePermissions', function (done) {

      var queue = [],
          role, role2;

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test';
          entity.grant('test permission');
          role = entity;

          next();

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test2';
          entity.grant('test permission 2');
          role2 = entity;

          next();

        }, 'acl-role');

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.grant(role);
          entity.grant(role2);

          test.bool(
            entity.access(['test permission', 'test permission 2'])
          ).isTrue();

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

    it('shouldReturnFalseIfRoleIsString', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.grant('role');

          test.bool(
            entity.access('test perimssion')
          ).isNotTrue();

          next();

        }, 'acl-user');

      });

      async.series(queue, done);

    });

  });

  describe('User.passwordMatch()', function () {

    it('shouldReturnTrueIfPasswordsMatch', function (done) {

      var queue = [],
          user;

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          user = entity;
          user.set('password', 'hello', next);

        }, 'acl-user');

      });

      queue.push(function (next) {

        test.string(
          user.get('password')
        ).isNot('hello');

        test.bool(
          user.passwordMatch('hello')
        ).isTrue();

        next();

      });

      async.series(queue, done);

    });

    it('shouldReturnFalseIfPasswordsDontMatch', function (done) {

      var queue = [],
          user;

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          user = entity;
          user.set('password', 'hello', next);

        }, 'acl-user');

      });

      queue.push(function (next) {

        test.bool(
          user.passwordMatch('foobar')
        ).isNotTrue();

        next();

      });

      async.series(queue, done);

    });

  });

  describe('User.save()', function () {

    it('shouldSaveTheEntity', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test-role';

          var q2 = [];

          q2.push(function (nxt) {

            entity.set('title', 'Test role', nxt);

          });

          q2.push(function (nxt) {

            entity.set('description', 'This is a test role.', nxt);

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

          entity.machineName = 'test-user';

          var q2 = [];

          q2.push(function (nxt) {

            entity.set('email', 'test@test.dev', nxt);

          });

          q2.push(function (nxt) {

            entity.set('password', 'password', nxt);

          });

          q2.push(function (nxt) {

            entity.grant('test-role', nxt);

          });

          q2.push(function (nxt) {

            entity.save(nxt);

          });

          async.series(q2, next);

        }, 'acl-user');

      });

      queue.push(function (next) {

        core.entityManager.schema('acl-user', function (err, schema) {

          if (err) {
            return next(err);
          }

          schema.entityCollection.find(function (err, docs) {

            if (err) {
              return next(err);
            }

            test.array(
              docs
            ).hasLength(1);

            test.object(docs[0])
              .hasKey('machineName', 'test-user')
              .hasKey('type', 'acl-user')
              .hasKey('fieldData');

            test.object(docs[0].fieldData)
              .hasKey('email', 'test@test.dev')
              .hasKey('roles');

            test.object(docs[0].fieldData.roles)
              .hasKey('test-role');

            test.object(
              docs[0].fieldData.roles['test-role']
            ).is({
              type: 'acl-role',
              subtype: null,
              machineName: 'test-role'
            });

            next();

          });

        });

      });

      async.series(queue, done);

    });

  });

  describe('User.load()', function () {

    it('shouldLoadTheEntity', function (done) {

      var queue = [];

      queue.push(function (next) {

        loader('EntityACL/User')(core, next);

      });

      queue.push(function (next) {

        core.entityManager.create(function (err, entity) {

          if (err) {
            return next(err);
          }

          entity.machineName = 'test-role';

          var q2 = [];

          q2.push(function (nxt) {

            entity.set('title', 'Test role', nxt);

          });

          q2.push(function (nxt) {

            entity.set('description', 'This is a test role.', nxt);

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

          entity.machineName = 'test-user';

          var q2 = [];

          q2.push(function (nxt) {

            entity.set('email', 'test@test.dev', nxt);

          });

          q2.push(function (nxt) {

            entity.set('password', 'password', nxt);

          });

          q2.push(function (nxt) {

            entity.grant('test-role', nxt);

          });

          q2.push(function (nxt) {

            entity.save(nxt);

          });

          async.series(q2, next);

        }, 'acl-user');

      });

      queue.push(function (next) {

        core.entityManager.load(
          'acl-user',
          'test-user',
          function (err, entity) {

            if (err) {
              return next(err);
            }

            test.string(
              entity.get('email')
            ).is('test@test.dev');

            var roles = entity.get('roles');
            test.object(roles)
              .hasKey('test-role');

            test.object(roles['test-role'])
              .isInstanceOf(Entity)
              .hasKey('machineName', 'test-role');

            test.bool(
              entity.granted('test-role')
            ).isTrue();

            next();

          }
        );

      });

      async.series(queue, done);

    });

  });

});
