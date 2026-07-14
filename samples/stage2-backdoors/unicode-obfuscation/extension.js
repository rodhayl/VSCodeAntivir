// [FAKE-DEMO] Inert sample for hidden Unicode escape detections.
const hidden = "\\u200b\\u200d\\ufeff";
const builder = String.fromCharCode(8203) + hidden;

function activate() {
  return builder;
}

module.exports = { activate };
