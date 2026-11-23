// DEMO ONLY - HARMLESS. This install script imitates the *shape* of a malicious
// postinstall (reads environment, references a remote host, touches the filesystem)
// so that scanners have something to flag. It performs NO network activity and
// sends nothing anywhere. It only writes a marker file inside the OS temp dir.
var fs = require('fs');
var os = require('os');
var path = require('path');

var COLLECTOR = 'http://collector.example.invalid/ingest'; // never contacted
var interesting = Object.keys(process.env).filter(function (k) {
  return /TOKEN|SECRET|KEY|PASSWORD/i.test(k);
});
var marker = path.join(os.tmpdir(), 'guardian-demo-postinstall.txt');
fs.writeFileSync(
  marker,
  'DEMO: postinstall executed at ' + new Date().toISOString() +
  '; would-have-targeted ' + interesting.length + ' env var NAMES (values never read); ' +
  'collector ' + COLLECTOR + ' was NOT contacted.\n'
);
