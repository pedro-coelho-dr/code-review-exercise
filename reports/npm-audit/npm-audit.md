```txt

# npm audit report

base64url  <3.0.0
Severity: moderate
Out-of-bounds Read in base64url - https://github.com/advisories/GHSA-rvg8-pwq2-xj7q
fix available via `npm audit fix --force`
Will install jsonwebtoken@9.0.2, which is a breaking change
node_modules/base64url
  jwa  <=1.1.5
  Depends on vulnerable versions of base64url
  node_modules/jwa
    jws  <=3.1.4
    Depends on vulnerable versions of base64url
    Depends on vulnerable versions of jwa
    node_modules/jws
      jsonwebtoken  <=8.5.1
      Depends on vulnerable versions of jws
      Depends on vulnerable versions of moment
      node_modules/express-jwt/node_modules/jsonwebtoken
      node_modules/jsonwebtoken
        express-jwt  <=7.7.7
        Depends on vulnerable versions of jsonwebtoken
        node_modules/express-jwt

braces  <3.0.3
Severity: high
Uncontrolled resource consumption in braces - https://github.com/advisories/GHSA-grv7-fg5c-xmjg
fix available via `npm audit fix --force`
Will install check-dependencies@2.0.0, which is a breaking change
node_modules/braces
  micromatch  <=4.0.7
  Depends on vulnerable versions of braces
  node_modules/micromatch
    anymatch  1.2.0 - 2.0.0
    Depends on vulnerable versions of micromatch
    node_modules/sane/node_modules/anymatch
      sane  1.5.0 - 4.1.0
      Depends on vulnerable versions of anymatch
      Depends on vulnerable versions of micromatch
      node_modules/sane
        jest-haste-map  24.0.0-alpha.0 - 26.6.2
        Depends on vulnerable versions of sane
        node_modules/jest-haste-map
          @jest/core  <=26.6.3
          Depends on vulnerable versions of @jest/reporters
          Depends on vulnerable versions of @jest/transform
          Depends on vulnerable versions of jest-config
          Depends on vulnerable versions of jest-haste-map
          Depends on vulnerable versions of jest-resolve-dependencies
          Depends on vulnerable versions of jest-runner
          Depends on vulnerable versions of jest-runtime
          Depends on vulnerable versions of jest-snapshot
          node_modules/@jest/core
            jest  24.2.0-alpha.0 - 26.6.3
            Depends on vulnerable versions of @jest/core
            Depends on vulnerable versions of jest-cli
            node_modules/jest
              ts-jest  25.10.0-alpha.1 - 27.0.0-next.12
              Depends on vulnerable versions of jest
              node_modules/ts-jest
            jest-cli  24.2.0-alpha.0 - 26.6.3
            Depends on vulnerable versions of @jest/core
            Depends on vulnerable versions of jest-config
            node_modules/jest-cli
          @jest/reporters  <=26.6.2
          Depends on vulnerable versions of @jest/transform
          Depends on vulnerable versions of jest-haste-map
          node_modules/@jest/reporters
          @jest/test-sequencer  <=26.6.3
          Depends on vulnerable versions of jest-haste-map
          Depends on vulnerable versions of jest-runner
          Depends on vulnerable versions of jest-runtime
          node_modules/@jest/test-sequencer
            jest-config  24.2.0-alpha.0 - 26.6.3
            Depends on vulnerable versions of @jest/test-sequencer
            Depends on vulnerable versions of babel-jest
            Depends on vulnerable versions of jest-jasmine2
            node_modules/jest-config
              jest-runner  24.0.0-alpha.0 - 26.6.3
              Depends on vulnerable versions of jest-config
              Depends on vulnerable versions of jest-haste-map
              Depends on vulnerable versions of jest-runtime
              node_modules/jest-runner
              jest-runtime  24.0.0-alpha.0 - 26.6.3
              Depends on vulnerable versions of @jest/transform
              Depends on vulnerable versions of jest-config
              Depends on vulnerable versions of jest-haste-map
              Depends on vulnerable versions of jest-snapshot
              node_modules/jest-runtime
                jest-jasmine2  24.2.0-alpha.0 - 26.6.3
                Depends on vulnerable versions of jest-runtime
                Depends on vulnerable versions of jest-snapshot
                node_modules/jest-jasmine2
          @jest/transform  <=26.6.2
          Depends on vulnerable versions of jest-haste-map
          node_modules/@jest/transform
            babel-jest  24.2.0-alpha.0 - 26.6.3
            Depends on vulnerable versions of @jest/transform
            node_modules/babel-jest
          jest-snapshot  24.2.0-alpha.0 - 24.5.0 || 26.1.0 - 26.6.2
          Depends on vulnerable versions of jest-haste-map
          node_modules/jest-snapshot
            jest-resolve-dependencies  26.1.0 - 26.6.3
            Depends on vulnerable versions of jest-snapshot
            node_modules/jest-resolve-dependencies
    findup-sync  0.4.0 - 3.0.0
    Depends on vulnerable versions of micromatch
    node_modules/findup-sync
      check-dependencies  0.12.1 - 1.1.1
      Depends on vulnerable versions of findup-sync
      node_modules/check-dependencies

cookie  <0.7.0
cookie accepts cookie name, path, and domain with out of bounds characters - https://github.com/advisories/GHSA-pxg6-pf52-xh8x
fix available via `npm audit fix --force`
Will install socket.io@4.8.1, which is a breaking change
node_modules/engine.io/node_modules/cookie
  engine.io  0.7.8 - 0.7.9 || 1.8.0 - 6.6.1
  Depends on vulnerable versions of cookie
  Depends on vulnerable versions of ws
  node_modules/engine.io
    socket.io  3.0.0-rc1 - 4.6.1
    Depends on vulnerable versions of engine.io
    node_modules/socket.io

crypto-js  <4.2.0
Severity: critical
crypto-js PBKDF2 1,000 times weaker than specified in 1993 and 1.3M times weaker than current standard - https://github.com/advisories/GHSA-xwcq-pm8m-c4vf
fix available via `npm audit fix --force`
Will install pdfkit@0.16.0, which is a breaking change
node_modules/crypto-js
  pdfkit  0.9.0 - 0.12.1
  Depends on vulnerable versions of crypto-js
  node_modules/pdfkit

ecstatic  <4.1.3
Severity: moderate
Denial of Service in ecstatic - https://github.com/advisories/GHSA-jc84-3g44-wf2q
fix available via `npm audit fix --force`
Will install http-server@14.1.1, which is a breaking change
node_modules/ecstatic
  http-server  0.4.0 - 0.12.3
  Depends on vulnerable versions of ecstatic
  node_modules/http-server



got  <=11.8.3
Severity: high
Got allows a redirect to a UNIX socket - https://github.com/advisories/GHSA-pfrx-2q88-qq97
Depends on vulnerable versions of cacheable-request
fix available via `npm audit fix --force`
Will install download@3.3.0, which is a breaking change
node_modules/got
  download  >=4.0.0
  Depends on vulnerable versions of got
  node_modules/download

http-cache-semantics  <4.1.1
Severity: high
http-cache-semantics vulnerable to Regular Expression Denial of Service - https://github.com/advisories/GHSA-rc47-6667-2j5j
fix available via `npm audit fix --force`
Will install download@3.3.0, which is a breaking change
node_modules/http-cache-semantics
  cacheable-request  0.1.0 - 2.1.4
  Depends on vulnerable versions of http-cache-semantics
  node_modules/cacheable-request

ip  *
Severity: high
ip SSRF improper categorization in isPublic - https://github.com/advisories/GHSA-2p57-rm9w-gvfp
No fix available
node_modules/ip
  express-ipfilter  *
  Depends on vulnerable versions of ip
  node_modules/express-ipfilter



libxmljs  *
Severity: critical
libxmljs vulnerable to type confusion when parsing specially crafted XML  - https://github.com/advisories/GHSA-mg49-jqgw-gcj6
libxmljs vulnerable to type confusion when parsing specially crafted XML - https://github.com/advisories/GHSA-6433-x5p4-8jc7
No fix available
node_modules/libxmljs

libxmljs2  *
Severity: critical
libxmljs2 vulnerable to type confusion when parsing specially crafted XML - https://github.com/advisories/GHSA-78h3-pg4x-j8cv
fix available via `npm audit fix --force`
Will install @cyclonedx/cyclonedx-npm@1.10.0, which is a breaking change
node_modules/libxmljs2
  @cyclonedx/cyclonedx-library  >=1.14.0-rc.0
  Depends on vulnerable versions of libxmljs2
  node_modules/@cyclonedx/cyclonedx-library
    @cyclonedx/cyclonedx-npm  >=1.11.0
    Depends on vulnerable versions of @cyclonedx/cyclonedx-library
    node_modules/@cyclonedx/cyclonedx-npm

lodash  <=4.17.20
Severity: critical
Regular Expression Denial of Service (ReDoS) in lodash - https://github.com/advisories/GHSA-x5rq-j2xg-h7qm
Prototype Pollution in lodash - https://github.com/advisories/GHSA-4xc9-xhrj-v574
Regular Expression Denial of Service (ReDoS) in lodash - https://github.com/advisories/GHSA-29mw-wpgm-hmr9
Command Injection in lodash - https://github.com/advisories/GHSA-35jh-r3h4-6jhm
Prototype Pollution in lodash - https://github.com/advisories/GHSA-fvqr-27wr-82fm
Prototype Pollution in lodash - https://github.com/advisories/GHSA-jf85-cpcp-j695
fix available via `npm audit fix --force`
Will install sanitize-html@1.27.5, which is outside the stated dependency range
node_modules/sanitize-html/node_modules/lodash
  sanitize-html  <=2.12.0
  Depends on vulnerable versions of lodash
  node_modules/sanitize-html

lodash.set  *
Severity: high
Prototype Pollution in lodash - https://github.com/advisories/GHSA-p6mc-m468-83gw
No fix available
node_modules/lodash.set
  grunt-replace-json  *
  Depends on vulnerable versions of lodash.set
  node_modules/grunt-replace-json

marsdb  *
Severity: critical
Command Injection in marsdb - https://github.com/advisories/GHSA-5mrr-rgp6-x4gr
No fix available
node_modules/marsdb


minimatch  <3.0.5
Severity: high
minimatch ReDoS vulnerability - https://github.com/advisories/GHSA-f8q6-p94x-37v3
fix available via `npm audit fix --force`
Will install mocha@11.0.1, which is a breaking change
node_modules/mocha/node_modules/minimatch
  mocha  5.1.0 - 10.2.0
  Depends on vulnerable versions of minimatch
  Depends on vulnerable versions of nanoid
  node_modules/mocha

moment  <=2.29.1
Severity: high
Regular Expression Denial of Service in moment - https://github.com/advisories/GHSA-87vv-r9j6-g5qv
Regular Expression Denial of Service in moment - https://github.com/advisories/GHSA-446m-mv8f-q348
Path Traversal: 'dir/../../filename' in moment.locale - https://github.com/advisories/GHSA-8hfj-j24r-96c4
fix available via `npm audit fix --force`
Will install jsonwebtoken@9.0.2, which is a breaking change
node_modules/express-jwt/node_modules/moment

nanoid  <=3.3.7
Severity: moderate
Exposure of Sensitive Information to an Unauthorized Actor in nanoid - https://github.com/advisories/GHSA-qrpm-p2h7-hrv2
Predictable results in nanoid generation when given non-integer values - https://github.com/advisories/GHSA-mwcw-c2x4-8c55
fix available via `npm audit fix --force`
Will install mocha@11.0.1, which is a breaking change
node_modules/nanoid

notevil  *
Severity: moderate
Sandbox escape in notevil and argencoders-notevil - https://github.com/advisories/GHSA-8g4m-cjm2-96wq
No fix available
node_modules/notevil

request  *
Severity: moderate
Server-Side Request Forgery in Request - https://github.com/advisories/GHSA-p8p7-x288-28g6
Depends on vulnerable versions of tough-cookie
No fix available
node_modules/request



socket.io-parser  4.0.4 - 4.2.2
Severity: moderate
Insufficient validation when decoding a Socket.IO packet - https://github.com/advisories/GHSA-cqmj-92xf-r6r9
fix available via `npm audit fix --force`
Will install socket.io-client@4.8.1, which is a breaking change
node_modules/socket.io-parser
  socket.io-client  1.0.0-pre - 1.0.1 || 3.0.0-rc1 - 4.4.1
  Depends on vulnerable versions of engine.io-client
  Depends on vulnerable versions of socket.io-parser
  node_modules/socket.io-client

tar  <6.2.1
Severity: moderate
Denial of service while parsing a tar file due to lack of folders count validation - https://github.com/advisories/GHSA-f5x3-32g6-xq36
No fix available
node_modules/node-pre-gyp/node_modules/tar
  node-pre-gyp  *
  Depends on vulnerable versions of tar
  node_modules/node-pre-gyp

tough-cookie  <4.1.3
Severity: moderate
tough-cookie Prototype Pollution vulnerability - https://github.com/advisories/GHSA-72xf-g2v4-qvf3
No fix available
node_modules/request/node_modules/tough-cookie

vm2  *
Severity: critical
vm2 Sandbox Escape vulnerability - https://github.com/advisories/GHSA-cchq-frgv-rjh5
vm2 Sandbox Escape vulnerability - https://github.com/advisories/GHSA-whpj-8f3w-67p5
vm2 vulnerable to Inspect Manipulation - https://github.com/advisories/GHSA-p5gc-c584-jj6v
vm2 Sandbox Escape vulnerability - https://github.com/advisories/GHSA-g644-9gfx-q4q4
fix available via `npm audit fix --force`
Will install juicy-chat-bot@0.6.4, which is a breaking change
node_modules/vm2
  juicy-chat-bot  >=0.6.5
  Depends on vulnerable versions of vm2
  node_modules/juicy-chat-bot

ws  7.0.0 - 7.5.9
Severity: high
ws affected by a DoS when handling a request with many HTTP headers - https://github.com/advisories/GHSA-3h5v-q93c-6h6q
fix available via `npm audit fix --force`
Will install socket.io@4.8.1, which is a breaking change
node_modules/engine.io-client/node_modules/ws
node_modules/engine.io/node_modules/ws
  engine.io-client  0.7.0 || 0.7.8 - 0.7.9 || 3.5.0 - 3.5.3 || 4.0.0-alpha.0 - 5.2.0
  Depends on vulnerable versions of ws
  node_modules/engine.io-client

63 vulnerabilities (1 low, 33 moderate, 19 high, 10 critical)

To address issues that do not require attention, run:
  npm audit fix

To address all issues possible (including breaking changes), run:
  npm audit fix --force

Some issues need review, and may require choosing
a different dependency.
```
