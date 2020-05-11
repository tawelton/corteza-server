CREATE TABLE IF NOT EXISTS sys_auditlog (
  ts               DATETIME        NOT NULL DEFAULT NOW(),
  request_ip       VARCHAR(64)     NOT NULL,
  user_id          BIGINT          UNSIGNED,
  request_id       VARCHAR(64)     NOT NULL,
  severity         SMALLINT        NOT NULL,
  target           VARCHAR(64)     NOT NULL,
  event            VARCHAR(64)     NOT NULL,
  description      TEXT,
  meta             JSON

) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE INDEX ts     ON sys_auditlog (ts DESC);
CREATE INDEX `user` ON sys_auditlog (user_id);
CREATE INDEX target ON sys_auditlog (target);
