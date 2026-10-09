// Experimental Egern YouTube /youtubei/v1/next filter.
// Tested against one captured protobuf response. Fail-open on unknown layouts.
export default async function (ctx) {
  const original = new Uint8Array(await ctx.response.arrayBuffer());
  if (!original) return;
  const input = original instanceof Uint8Array ? original : new Uint8Array(original);
  const decoder = new TextDecoder();
  function varint(data, pos) {
    let n = 0, m = 1;
    for (let i = 0; i < 9; i++) {
      if (pos >= data.length) throw Error('short varint');
      const x = data[pos++];
      n += (x & 127) * m;
      if (x < 128) {
        if (!Number.isSafeInteger(n)) throw Error('unsafe varint');
        return [n, pos];
      }
      m *= 128;
    }
    throw Error('long varint');
  }
  function encodeVarint(n) {
    const a = [];
    do { const x = n % 128; n = Math.floor(n / 128); a.push(x | (n ? 128 : 0)); } while (n);
    return Uint8Array.from(a);
  }
  function concat(parts) {
    let size = 0; for (const p of parts) size += p.length;
    const out = new Uint8Array(size); let off = 0;
    for (const p of parts) { out.set(p, off); off += p.length; }
    return out;
  }
  function readFields(data) {
    const fields = [];
    let pos = 0;
    while (pos < data.length) {
      const start = pos;
      let tag; [tag, pos] = varint(data, pos);
      const num = Math.floor(tag / 8), wire = tag % 8;
      if (!num) throw Error('bad tag');
      let bodyStart = pos, bodyEnd;
      if (wire === 2) {
        let length; [length, pos] = varint(data, pos);
        bodyStart = pos; bodyEnd = pos + length; pos = bodyEnd;
      } else if (wire === 0) {
        [, pos] = varint(data, pos); bodyEnd = pos;
      } else if (wire === 1 || wire === 5) {
        pos += wire === 1 ? 8 : 4; bodyEnd = pos;
      } else throw Error('unsupported wire type');
      if (pos > data.length) throw Error('truncated field');
      fields.push({num, wire, raw:data.subarray(start,pos), body:data.subarray(bodyStart,bodyEnd)});
    }
    return fields;
  }
  function encodedField(num, body) {
    return concat([encodeVarint(num * 8 + 2), encodeVarint(body.length), body]);
  }
  // The validated nesting for the captured iOS watch-page response:
  // root.7.51779735.1.49399797 contains repeated field-1 page sections.
  const path = [7, 51779735, 1, 49399797];
  let removed = 0;
  function transform(data, depth) {
    const fields = readFields(data), result = [];
    for (const f of fields) {
      if (depth === path.length && f.num === 1 && f.wire === 2) {
        // Only skip complete recommendation sections identified by their exact marker.
        if (decoder.decode(f.body).includes('related-items')) { removed++; continue; }
      }
      if (depth < path.length && f.num === path[depth] && f.wire === 2) {
        const changed = transform(f.body, depth+1);
        result.push(changed === f.body ? f.raw : encodedField(f.num,changed));
      } else result.push(f.raw);
    }
    if (removed === 0 && depth === path.length) return data;
    return concat(result);
  }
  try {
    const output = transform(input, 0);
    if (removed < 1 || removed > 30) { // Fail open if no identifiable related sections or suspicious layout.
      console.log('Unexpected YouTube layout; leaving response unmodified. Related sections: ' + removed);
      return;
    }
    console.log('Removed YouTube related sections: ' + removed);
    return {body:output};
  } catch (e) {
    console.log('YouTube recommendation filtering error: ' + e);
    return;
  }
}