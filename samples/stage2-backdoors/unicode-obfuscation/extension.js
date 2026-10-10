// TEXT-ONLY INSPECTION SAMPLE for hidden Unicode escape detections.
// Inspect as text; do not run, import or activate sample code.
const hidden = "\\u200b\\u200d\\ufeff";
const builder = String.fromCharCode(8203) + hidden;

function activate() {
  return builder;
}

module.exports = { activate };
