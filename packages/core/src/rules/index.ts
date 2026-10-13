// Built-in rule registry. Each rule lives in its own file (CONTRIBUTING.md).
import type { Rule } from "../types.js";
import { SEC_001 } from "./secrets/SEC-001.js";
import { SEC_002 } from "./secrets/SEC-002.js";
import { SEC_003 } from "./secrets/SEC-003.js";
import { SEC_004 } from "./secrets/SEC-004.js";
import { SEC_005 } from "./secrets/SEC-005.js";
import { SEC_007 } from "./secrets/SEC-007.js";
import { SEC_INFO_001 } from "./secrets/SEC-INFO-001.js";
import { DB_001 } from "./data/DB-001.js";
import { DB_002 } from "./data/DB-002.js";
import { DB_003 } from "./data/DB-003.js";
import { DB_004 } from "./data/DB-004.js";
import { DB_005 } from "./data/DB-005.js";
import { DB_006 } from "./data/DB-006.js";
import { DEP_001 } from "./deps/DEP-001.js";
import { DEP_002 } from "./deps/DEP-002.js";
import { DEP_003 } from "./deps/DEP-003.js";
import { DEP_004 } from "./deps/DEP-004.js";
import { DEP_005 } from "./deps/DEP-005.js";
import { CODE_001 } from "./code/CODE-001.js";
import { CODE_002 } from "./code/CODE-002.js";
import { CODE_003 } from "./code/CODE-003.js";
import { CODE_004 } from "./code/CODE-004.js";
import { CODE_005 } from "./code/CODE-005.js";
import { CODE_006 } from "./code/CODE-006.js";
import { CODE_INV_001 } from "./code/CODE-INV-001.js";
import { WEB_001 } from "./web/WEB-001.js";
import { WEB_002 } from "./web/WEB-002.js";
import { WEB_003 } from "./web/WEB-003.js";
import { WEB_004 } from "./web/WEB-004.js";
import { WEB_005 } from "./web/WEB-005.js";
import { WEB_006 } from "./web/WEB-006.js";
import { WEB_007 } from "./web/WEB-007.js";
import { WEB_008 } from "./web/WEB-008.js";
import { WEB_009 } from "./web/WEB-009.js";
import { WEB_010 } from "./web/WEB-010.js";
import { WEB_011 } from "./web/WEB-011.js";
import { WEB_012 } from "./web/WEB-012.js";
import { WEB_013 } from "./web/WEB-013.js";
import { WEB_014 } from "./web/WEB-014.js";
import { WEB_015 } from "./web/WEB-015.js";
import { WEB_016 } from "./web/WEB-016.js";
import { WEB_017 } from "./web/WEB-017.js";
import { WEB_018 } from "./web/WEB-018.js";
import { CFG_INFO_001 } from "./config/CFG-INFO-001.js";
import { CFG_INFO_002 } from "./config/CFG-INFO-002.js";
import { CFG_001 } from "./config/CFG-001.js";
import { CFG_002 } from "./config/CFG-002.js";
import { CFG_003 } from "./config/CFG-003.js";
import { CFG_004 } from "./config/CFG-004.js";
import { CFG_005 } from "./config/CFG-005.js";
import { CFG_006 } from "./config/CFG-006.js";

export const DEFAULT_RULES: readonly Rule[] = [
  SEC_001,
  SEC_002,
  SEC_003,
  SEC_004,
  SEC_005,
  SEC_007,
  SEC_INFO_001,
  DB_001,
  DB_002,
  DB_003,
  DB_004,
  DB_005,
  DB_006,
  DEP_001,
  DEP_002,
  DEP_003,
  DEP_004,
  DEP_005,
  CODE_001,
  CODE_002,
  CODE_003,
  CODE_004,
  CODE_005,
  CODE_006,
  CODE_INV_001,
  CFG_001,
  CFG_002,
  CFG_003,
  CFG_004,
  CFG_005,
  CFG_006,
  CFG_INFO_001,
  CFG_INFO_002,
  WEB_001,
  WEB_002,
  WEB_003,
  WEB_004,
  WEB_005,
  WEB_006,
  WEB_007,
  WEB_008,
  WEB_009,
  WEB_010,
  WEB_011,
  WEB_012,
  WEB_013,
  WEB_014,
  WEB_015,
  WEB_016,
  WEB_017,
  WEB_018,
];
