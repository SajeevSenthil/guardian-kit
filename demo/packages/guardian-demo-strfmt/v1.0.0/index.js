// DEMO ONLY: tiny, harmless string formatting helper used to exercise the Guardian.
module.exports = { pad: function (s, n) { s = String(s); while (s.length < n) s = ' ' + s; return s; } };
