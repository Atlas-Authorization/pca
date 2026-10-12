// Dafny program Merkle.dfy compiled into JavaScript
// Copyright by the contributors to the Dafny Project
// SPDX-License-Identifier: MIT

const BigNumber = require('bignumber.js');
BigNumber.config({ MODULO_MODE: BigNumber.EUCLID })
let _dafny = (function() {
  let $module = {};
  $module.areEqual = function(a, b) {
    if (typeof a === 'string' && b instanceof _dafny.Seq) {
      // Seq.equals(string) works as expected,
      // and the catch-all else block handles that direction.
      // But the opposite direction doesn't work; handle it here.
      return b.equals(a);
    } else if (typeof a === 'number' && BigNumber.isBigNumber(b)) {
      // This conditional would be correct even without the `typeof a` part,
      // but in most cases it's probably faster to short-circuit on a `typeof`
      // than to call `isBigNumber`. (But it remains to properly test this.)
      return b.isEqualTo(a);
    } else if (typeof a !== 'object' || a === null || b === null) {
      return a === b;
    } else if (BigNumber.isBigNumber(a)) {
      return a.isEqualTo(b);
    } else if (a._tname !== undefined || (Array.isArray(a) && a.constructor.name == "Array")) {
      return a === b;  // pointer equality
    } else {
      return a.equals(b);  // value-type equality
    }
  }
  $module.toString = function(a) {
    if (a === null) {
      return "null";
    } else if (typeof a === "number") {
      return a.toFixed();
    } else if (BigNumber.isBigNumber(a)) {
      return a.toFixed();
    } else if (a._tname !== undefined) {
      return a._tname;
    } else {
      return a.toString();
    }
  }
  $module.escapeCharacter = function(cp) {
    let s = String.fromCodePoint(cp.value)
    switch (s) {
      case '\n': return "\\n";
      case '\r': return "\\r";
      case '\t': return "\\t";
      case '\0': return "\\0";
      case '\'': return "\\'";
      case '\"': return "\\\"";
      case '\\': return "\\\\";
      default: return s;
    };
  }
  $module.NewObject = function() {
    return { _tname: "object" };
  }
  $module.InstanceOfTrait = function(obj, trait) {
    return obj._parentTraits !== undefined && obj._parentTraits().includes(trait);
  }
  $module.Rtd_bool = class {
    static get Default() { return false; }
  }
  $module.Rtd_char = class {
    static get Default() { return 'D'; }  // See CharType.DefaultValue in Dafny source code
  }
  $module.Rtd_codepoint = class {
    static get Default() { return new _dafny.CodePoint('D'.codePointAt(0)); }
  }
  $module.Rtd_int = class {
    static get Default() { return BigNumber(0); }
  }
  $module.Rtd_number = class {
    static get Default() { return 0; }
  }
  $module.Rtd_ref = class {
    static get Default() { return null; }
  }
  $module.Rtd_array = class {
    static get Default() { return []; }
  }
  $module.ZERO = new BigNumber(0);
  $module.ONE = new BigNumber(1);
  $module.NUMBER_LIMIT = new BigNumber(0x20).multipliedBy(0x1000000000000);  // 2^53
  $module.Tuple = class Tuple extends Array {
    constructor(...elems) {
      super(...elems);
    }
    toString() {
      return "(" + arrayElementsToString(this) + ")";
    }
    equals(other) {
      if (this === other) {
        return true;
      }
      for (let i = 0; i < this.length; i++) {
        if (!_dafny.areEqual(this[i], other[i])) {
          return false;
        }
      }
      return true;
    }
    static Default(...values) {
      return Tuple.of(...values);
    }
    static Rtd(...rtdArgs) {
      return {
        Default: Tuple.from(rtdArgs, rtd => rtd.Default)
      };
    }
  }
  $module.Set = class Set extends Array {
    constructor() {
      super();
    }
    static get Default() {
      return Set.Empty;
    }
    toString() {
      return "{" + arrayElementsToString(this) + "}";
    }
    static get Empty() {
      if (this._empty === undefined) {
        this._empty = new Set();
      }
      return this._empty;
    }
    static fromElements(...elmts) {
      let s = new Set();
      for (let k of elmts) {
        s.add(k);
      }
      return s;
    }
    contains(k) {
      for (let i = 0; i < this.length; i++) {
        if (_dafny.areEqual(this[i], k)) {
          return true;
        }
      }
      return false;
    }
    add(k) {  // mutates the Set; use only during construction
      if (!this.contains(k)) {
        this.push(k);
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.length !== other.length) {
        return false;
      }
      for (let e of this) {
        if (!other.contains(e)) {
          return false;
        }
      }
      return true;
    }
    get Elements() {
      return this;
    }
    Union(that) {
      if (this.length === 0) {
        return that;
      } else if (that.length === 0) {
        return this;
      } else {
        let s = Set.of(...this);
        for (let k of that) {
          s.add(k);
        }
        return s;
      }
    }
    Intersect(that) {
      if (this.length === 0) {
        return this;
      } else if (that.length === 0) {
        return that;
      } else {
        let s = new Set();
        for (let k of this) {
          if (that.contains(k)) {
            s.push(k);
          }
        }
        return s;
      }
    }
    Difference(that) {
      if (this.length == 0 || that.length == 0) {
        return this;
      } else {
        let s = new Set();
        for (let k of this) {
          if (!that.contains(k)) {
            s.push(k);
          }
        }
        return s;
      }
    }
    IsDisjointFrom(that) {
      for (let k of this) {
        if (that.contains(k)) {
          return false;
        }
      }
      return true;
    }
    IsSubsetOf(that) {
      if (that.length < this.length) {
        return false;
      }
      for (let k of this) {
        if (!that.contains(k)) {
          return false;
        }
      }
      return true;
    }
    IsProperSubsetOf(that) {
      if (that.length <= this.length) {
        return false;
      }
      for (let k of this) {
        if (!that.contains(k)) {
          return false;
        }
      }
      return true;
    }
    get AllSubsets() {
      return this.AllSubsets_();
    }
    *AllSubsets_() {
      // Start by putting all set elements into a list, but don't include null
      let elmts = Array.of(...this);
      let n = elmts.length;
      let which = new Array(n);
      which.fill(false);
      let a = [];
      while (true) {
        yield Set.of(...a);
        // "add 1" to "which", as if doing a carry chain.  For every digit changed, change the membership of the corresponding element in "a".
        let i = 0;
        for (; i < n && which[i]; i++) {
          which[i] = false;
          // remove elmts[i] from a
          for (let j = 0; j < a.length; j++) {
            if (_dafny.areEqual(a[j], elmts[i])) {
              // move the last element of a into slot j
              a[j] = a[-1];
              a.pop();
              break;
            }
          }
        }
        if (i === n) {
          // we have cycled through all the subsets
          break;
        }
        which[i] = true;
        a.push(elmts[i]);
      }
    }
  }
  $module.MultiSet = class MultiSet extends Array {
    constructor() {
      super();
    }
    static get Default() {
      return MultiSet.Empty;
    }
    toString() {
      let s = "multiset{";
      let sep = "";
      for (let e of this) {
        let [k, n] = e;
        let ks = _dafny.toString(k);
        while (!n.isZero()) {
          n = n.minus(1);
          s += sep + ks;
          sep = ", ";
        }
      }
      s += "}";
      return s;
    }
    static get Empty() {
      if (this._empty === undefined) {
        this._empty = new MultiSet();
      }
      return this._empty;
    }
    static fromElements(...elmts) {
      let s = new MultiSet();
      for (let e of elmts) {
        s.add(e, _dafny.ONE);
      }
      return s;
    }
    static FromArray(arr) {
      let s = new MultiSet();
      for (let e of arr) {
        s.add(e, _dafny.ONE);
      }
      return s;
    }
    cardinality() {
      let c = _dafny.ZERO;
      for (let e of this) {
        let [k, n] = e;
        c = c.plus(n);
      }
      return c;
    }
    clone() {
      let s = new MultiSet();
      for (let e of this) {
        let [k, n] = e;
        s.push([k, n]);  // make sure to create a new array [k, n] here
      }
      return s;
    }
    findIndex(k) {
      for (let i = 0; i < this.length; i++) {
        if (_dafny.areEqual(this[i][0], k)) {
          return i;
        }
      }
      return this.length;
    }
    get(k) {
      let i = this.findIndex(k);
      if (i === this.length) {
        return _dafny.ZERO;
      } else {
        return this[i][1];
      }
    }
    contains(k) {
      return !this.get(k).isZero();
    }
    add(k, n) {
      let i = this.findIndex(k);
      if (i === this.length) {
        this.push([k, n]);
      } else {
        let m = this[i][1];
        this[i] = [k, m.plus(n)];
      }
    }
    update(k, n) {
      let i = this.findIndex(k);
      if (i < this.length && this[i][1].isEqualTo(n)) {
        return this;
      } else if (i === this.length && n.isZero()) {
        return this;
      } else if (i === this.length) {
        let m = this.slice();
        m.push([k, n]);
        return m;
      } else {
        let m = this.slice();
        m[i] = [k, n];
        return m;
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      }
      for (let e of this) {
        let [k, n] = e;
        let m = other.get(k);
        if (!n.isEqualTo(m)) {
          return false;
        }
      }
      return this.cardinality().isEqualTo(other.cardinality());
    }
    get Elements() {
      return this.Elements_();
    }
    *Elements_() {
      for (let i = 0; i < this.length; i++) {
        let [k, n] = this[i];
        while (!n.isZero()) {
          yield k;
          n = n.minus(1);
        }
      }
    }
    get UniqueElements() {
      return this.UniqueElements_();
    }
    *UniqueElements_() {
      for (let e of this) {
        let [k, n] = e;
        if (!n.isZero()) {
          yield k;
        }
      }
    }
    Union(that) {
      if (this.length === 0) {
        return that;
      } else if (that.length === 0) {
        return this;
      } else {
        let s = this.clone();
        for (let e of that) {
          let [k, n] = e;
          s.add(k, n);
        }
        return s;
      }
    }
    Intersect(that) {
      if (this.length === 0) {
        return this;
      } else if (that.length === 0) {
        return that;
      } else {
        let s = new MultiSet();
        for (let e of this) {
          let [k, n] = e;
          let m = that.get(k);
          if (!m.isZero()) {
            s.push([k, m.isLessThan(n) ? m : n]);
          }
        }
        return s;
      }
    }
    Difference(that) {
      if (this.length === 0 || that.length === 0) {
        return this;
      } else {
        let s = new MultiSet();
        for (let e of this) {
          let [k, n] = e;
          let d = n.minus(that.get(k));
          if (d.isGreaterThan(0)) {
            s.push([k, d]);
          }
        }
        return s;
      }
    }
    IsDisjointFrom(that) {
      let intersection = this.Intersect(that);
      return intersection.cardinality().isZero();
    }
    IsSubsetOf(that) {
      for (let e of this) {
        let [k, n] = e;
        let m = that.get(k);
        if (!n.isLessThanOrEqualTo(m)) {
          return false;
        }
      }
      return true;
    }
    IsProperSubsetOf(that) {
      return this.IsSubsetOf(that) && this.cardinality().isLessThan(that.cardinality());
    }
  }
  $module.CodePoint = class CodePoint {
    constructor(value) {
      this.value = value
    }
    equals(other) {
      if (this === other) {
        return true;
      }
      return this.value === other.value
    }
    isLessThan(other) {
      return this.value < other.value
    }
    isLessThanOrEqual(other) {
      return this.value <= other.value
    }
    toString() {
      return "'" + $module.escapeCharacter(this) + "'";
    }
    static isCodePoint(i) {
      return (
        (_dafny.ZERO.isLessThanOrEqualTo(i) && i.isLessThan(new BigNumber(0xD800))) ||
        (new BigNumber(0xE000).isLessThanOrEqualTo(i) && i.isLessThan(new BigNumber(0x11_0000))))
    }
  }
  $module.Seq = class Seq extends Array {
    constructor(...elems) {
      super(...elems);
    }
    static get Default() {
      return Seq.of();
    }
    static Create(n, init) {
      return Seq.from({length: n}, (_, i) => init(new BigNumber(i)));
    }
    static UnicodeFromString(s) {
      return new Seq(...([...s].map(c => new _dafny.CodePoint(c.codePointAt(0)))))
    }
    toString() {
      return "[" + arrayElementsToString(this) + "]";
    }
    toVerbatimString(asLiteral) {
      if (asLiteral) {
        return '"' + this.map(c => _dafny.escapeCharacter(c)).join("") + '"';
      } else {
        return this.map(c => String.fromCodePoint(c.value)).join("");
      }
    }
    static update(s, i, v) {
      if (typeof s === "string") {
        let p = s.slice(0, i);
        let q = s.slice(i.toNumber() + 1);
        return p.concat(v, q);
      } else {
        let t = s.slice();
        t[i] = v;
        return t;
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.length !== other.length) {
        return false;
      }
      for (let i = 0; i < this.length; i++) {
        if (!_dafny.areEqual(this[i], other[i])) {
          return false;
        }
      }
      return true;
    }
    static contains(s, k) {
      if (typeof s === "string") {
        return s.includes(k);
      } else {
        for (let x of s) {
          if (_dafny.areEqual(x, k)) {
            return true;
          }
        }
        return false;
      }
    }
    get Elements() {
      return this;
    }
    get UniqueElements() {
      return _dafny.Set.fromElements(...this);
    }
    static Concat(a, b) {
      if (typeof a === "string" || typeof b === "string") {
        // string concatenation, so make sure both operands are strings before concatenating
        if (typeof a !== "string") {
          // a must be a Seq
          a = a.join("");
        }
        if (typeof b !== "string") {
          // b must be a Seq
          b = b.join("");
        }
        return a + b;
      } else {
        // ordinary concatenation
        let r = Seq.of(...a);
        r.push(...b);
        return r;
      }
    }
    static JoinIfPossible(x) {
      try { return x.join(""); } catch(_error) { return x; }
    }
    static IsPrefixOf(a, b) {
      if (b.length < a.length) {
        return false;
      }
      for (let i = 0; i < a.length; i++) {
        if (!_dafny.areEqual(a[i], b[i])) {
          return false;
        }
      }
      return true;
    }
    static IsProperPrefixOf(a, b) {
      if (b.length <= a.length) {
        return false;
      }
      for (let i = 0; i < a.length; i++) {
        if (!_dafny.areEqual(a[i], b[i])) {
          return false;
        }
      }
      return true;
    }
  }
  $module.Map = class Map extends Array {
    constructor() {
      super();
    }
    static get Default() {
      return Map.of();
    }
    toString() {
      return "map[" + this.map(maplet => _dafny.toString(maplet[0]) + " := " + _dafny.toString(maplet[1])).join(", ") + "]";
    }
    static get Empty() {
      if (this._empty === undefined) {
        this._empty = new Map();
      }
      return this._empty;
    }
    findIndex(k) {
      for (let i = 0; i < this.length; i++) {
        if (_dafny.areEqual(this[i][0], k)) {
          return i;
        }
      }
      return this.length;
    }
    get(k) {
      let i = this.findIndex(k);
      if (i === this.length) {
        return undefined;
      } else {
        return this[i][1];
      }
    }
    contains(k) {
      return this.findIndex(k) < this.length;
    }
    update(k, v) {
      let m = this.slice();
      m.updateUnsafe(k, v);
      return m;
    }
    // Similar to update, but make the modification in-place.
    // Meant to be used in the map constructor.
    updateUnsafe(k, v) {
      let m = this;
      let i = m.findIndex(k);
      m[i] = [k, v];
      return m;
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.length !== other.length) {
        return false;
      }
      for (let e of this) {
        let [k, v] = e;
        let w = other.get(k);
        if (w === undefined || !_dafny.areEqual(v, w)) {
          return false;
        }
      }
      return true;
    }
    get Keys() {
      let s = new _dafny.Set();
      for (let e of this) {
        let [k, v] = e;
        s.push(k);
      }
      return s;
    }
    get Values() {
      let s = new _dafny.Set();
      for (let e of this) {
        let [k, v] = e;
        s.add(v);
      }
      return s;
    }
    get Items() {
      let s = new _dafny.Set();
      for (let e of this) {
        let [k, v] = e;
        s.push(_dafny.Tuple.of(k, v));
      }
      return s;
    }
    Merge(that) {
      let m = that.slice();
      for (let e of this) {
        let [k, v] = e;
        let i = m.findIndex(k);
        if (i == m.length) {
          m[i] = [k, v];
        }
      }
      return m;
    }
    Subtract(keys) {
      if (this.length === 0 || keys.length === 0) {
        return this;
      }
      let m = new Map();
      for (let e of this) {
        let [k, v] = e;
        if (!keys.contains(k)) {
          m[m.length] = e;
        }
      }
      return m;
    }
  }
  $module.newArray = function(initValue, ...dims) {
    return { dims: dims, elmts: buildArray(initValue, ...dims) };
  }
  $module.BigOrdinal = class BigOrdinal {
    static get Default() {
      return _dafny.ZERO;
    }
    static IsLimit(ord) {
      return ord.isZero();
    }
    static IsSucc(ord) {
      return ord.isGreaterThan(0);
    }
    static Offset(ord) {
      return ord;
    }
    static IsNat(ord) {
      return true;  // at run time, every ORDINAL is a natural number
    }
  }
  $module.BigRational = class BigRational {
    static get ZERO() {
      if (this._zero === undefined) {
        this._zero = new BigRational(_dafny.ZERO);
      }
      return this._zero;
    }
    constructor (n, d) {
      // requires d === undefined || 1 <= d
      this.num = n;
      this.den = d === undefined ? _dafny.ONE : d;
      // invariant 1 <= den || (num == 0 && den == 0)
    }
    static get Default() {
      return _dafny.BigRational.ZERO;
    }
    // We need to deal with the special case `num == 0 && den == 0`, because
    // that's what C#'s default struct constructor will produce for BigRational. :(
    // To deal with it, we ignore `den` when `num` is 0.
    toString() {
      if (this.num.isZero() || this.den.isEqualTo(1)) {
        return this.num.toFixed() + ".0";
      }
      let answer = this.dividesAPowerOf10(this.den);
      if (answer !== undefined) {
        let n = this.num.multipliedBy(answer[0]);
        let log10 = answer[1];
        let sign, digits;
        if (this.num.isLessThan(0)) {
          sign = "-"; digits = n.negated().toFixed();
        } else {
          sign = ""; digits = n.toFixed();
        }
        if (log10 < digits.length) {
          let digitCount = digits.length - log10;
          return sign + digits.slice(0, digitCount) + "." + digits.slice(digitCount);
        } else {
          return sign + "0." + "0".repeat(log10 - digits.length) + digits;
        }
      } else {
        return "(" + this.num.toFixed() + ".0 / " + this.den.toFixed() + ".0)";
      }
    }
    isPowerOf10(x) {
      if (x.isZero()) {
        return undefined;
      }
      let log10 = 0;
      while (true) {  // invariant: x != 0 && x * 10^log10 == old(x)
        if (x.isEqualTo(1)) {
          return log10;
        } else if (x.mod(10).isZero()) {
          log10++;
          x = x.dividedToIntegerBy(10);
        } else {
          return undefined;
        }
      }
    }
    dividesAPowerOf10(i) {
      let factor = _dafny.ONE;
      let log10 = 0;
      if (i.isLessThanOrEqualTo(_dafny.ZERO)) {
        return undefined;
      }

      // invariant: 1 <= i && i * 10^log10 == factor * old(i)
      while (i.mod(10).isZero()) {
        i = i.dividedToIntegerBy(10);
       log10++;
      }

      while (i.mod(5).isZero()) {
        i = i.dividedToIntegerBy(5);
        factor = factor.multipliedBy(2);
        log10++;
      }
      while (i.mod(2).isZero()) {
        i = i.dividedToIntegerBy(2);
        factor = factor.multipliedBy(5);
        log10++;
      }

      if (i.isEqualTo(_dafny.ONE)) {
        return [factor, log10];
      } else {
        return undefined;
      }
    }
    toBigNumber() {
      if (this.num.isZero() || this.den.isEqualTo(1)) {
        return this.num;
      } else if (this.num.isGreaterThan(0)) {
        return this.num.dividedToIntegerBy(this.den);
      } else {
        return this.num.minus(this.den).plus(1).dividedToIntegerBy(this.den);
      }
    }
    isInteger() {
      return this.equals(new _dafny.BigRational(this.toBigNumber(), _dafny.ONE));
    }
    // Returns values such that aa/dd == a and bb/dd == b.
    normalize(b) {
      let a = this;
      let aa, bb, dd;
      if (a.num.isZero()) {
        aa = a.num;
        bb = b.num;
        dd = b.den;
      } else if (b.num.isZero()) {
        aa = a.num;
        dd = a.den;
        bb = b.num;
      } else {
        let gcd = BigNumberGcd(a.den, b.den);
        let xx = a.den.dividedToIntegerBy(gcd);
        let yy = b.den.dividedToIntegerBy(gcd);
        // We now have a == a.num / (xx * gcd) and b == b.num / (yy * gcd).
        aa = a.num.multipliedBy(yy);
        bb = b.num.multipliedBy(xx);
        dd = a.den.multipliedBy(yy);
      }
      return [aa, bb, dd];
    }
    compareTo(that) {
      // simple things first
      let asign = this.num.isZero() ? 0 : this.num.isLessThan(0) ? -1 : 1;
      let bsign = that.num.isZero() ? 0 : that.num.isLessThan(0) ? -1 : 1;
      if (asign < 0 && 0 <= bsign) {
        return -1;
      } else if (asign <= 0 && 0 < bsign) {
        return -1;
      } else if (bsign < 0 && 0 <= asign) {
        return 1;
      } else if (bsign <= 0 && 0 < asign) {
        return 1;
      }
      let [aa, bb, dd] = this.normalize(that);
      if (aa.isLessThan(bb)) {
        return -1;
      } else if (aa.isEqualTo(bb)){
        return 0;
      } else {
        return 1;
      }
    }
    equals(that) {
      return this.compareTo(that) === 0;
    }
    isLessThan(that) {
      return this.compareTo(that) < 0;
    }
    isAtMost(that) {
      return this.compareTo(that) <= 0;
    }
    plus(b) {
      let [aa, bb, dd] = this.normalize(b);
      return new BigRational(aa.plus(bb), dd);
    }
    minus(b) {
      let [aa, bb, dd] = this.normalize(b);
      return new BigRational(aa.minus(bb), dd);
    }
    negated() {
      return new BigRational(this.num.negated(), this.den);
    }
    multipliedBy(b) {
      return new BigRational(this.num.multipliedBy(b.num), this.den.multipliedBy(b.den));
    }
    dividedBy(b) {
      let a = this;
      // Compute the reciprocal of b
      let bReciprocal;
      if (b.num.isGreaterThan(0)) {
        bReciprocal = new BigRational(b.den, b.num);
      } else {
        // this is the case b.num < 0
        bReciprocal = new BigRational(b.den.negated(), b.num.negated());
      }
      return a.multipliedBy(bReciprocal);
    }
  }
  $module.EuclideanDivisionNumber = function(a, b) {
    if (0 <= a) {
      if (0 <= b) {
        // +a +b: a/b
        return Math.floor(a / b);
      } else {
        // +a -b: -(a/(-b))
        return -Math.floor(a / -b);
      }
    } else {
      if (0 <= b) {
        // -a +b: -((-a-1)/b) - 1
        return -Math.floor((-a-1) / b) - 1;
      } else {
        // -a -b: ((-a-1)/(-b)) + 1
        return Math.floor((-a-1) / -b) + 1;
      }
    }
  }
  $module.EuclideanDivision = function(a, b) {
    if (a.isGreaterThanOrEqualTo(0)) {
      if (b.isGreaterThanOrEqualTo(0)) {
        // +a +b: a/b
        return a.dividedToIntegerBy(b);
      } else {
        // +a -b: -(a/(-b))
        return a.dividedToIntegerBy(b.negated()).negated();
      }
    } else {
      if (b.isGreaterThanOrEqualTo(0)) {
        // -a +b: -((-a-1)/b) - 1
        return a.negated().minus(1).dividedToIntegerBy(b).negated().minus(1);
      } else {
        // -a -b: ((-a-1)/(-b)) + 1
        return a.negated().minus(1).dividedToIntegerBy(b.negated()).plus(1);
      }
    }
  }
  $module.EuclideanModuloNumber = function(a, b) {
    let bp = Math.abs(b);
    if (0 <= a) {
      // +a: a % bp
      return a % bp;
    } else {
      // c = ((-a) % bp)
      // -a: bp - c if c > 0
      // -a: 0 if c == 0
      let c = (-a) % bp;
      return c === 0 ? c : bp - c;
    }
  }
  $module.ShiftLeft = function(b, n) {
    return b.multipliedBy(new BigNumber(2).exponentiatedBy(n));
  }
  $module.ShiftRight = function(b, n) {
    return b.dividedToIntegerBy(new BigNumber(2).exponentiatedBy(n));
  }
  $module.RotateLeft = function(b, n, w) {  // truncate(b << n) | (b >> (w - n))
    let x = _dafny.ShiftLeft(b, n).mod(new BigNumber(2).exponentiatedBy(w));
    let y = _dafny.ShiftRight(b, w - n);
    return x.plus(y);
  }
  $module.RotateRight = function(b, n, w) {  // (b >> n) | truncate(b << (w - n))
    let x = _dafny.ShiftRight(b, n);
    let y = _dafny.ShiftLeft(b, w - n).mod(new BigNumber(2).exponentiatedBy(w));;
    return x.plus(y);
  }
  $module.BitwiseAnd = function(a, b) {
    let r = _dafny.ZERO;
    const m = _dafny.NUMBER_LIMIT;  // 2^53
    let h = _dafny.ONE;
    while (!a.isZero() && !b.isZero()) {
      let a0 = a.mod(m);
      let b0 = b.mod(m);
      r = r.plus(h.multipliedBy(a0 & b0));
      a = a.dividedToIntegerBy(m);
      b = b.dividedToIntegerBy(m);
      h = h.multipliedBy(m);
    }
    return r;
  }
  $module.BitwiseOr = function(a, b) {
    let r = _dafny.ZERO;
    const m = _dafny.NUMBER_LIMIT;  // 2^53
    let h = _dafny.ONE;
    while (!a.isZero() && !b.isZero()) {
      let a0 = a.mod(m);
      let b0 = b.mod(m);
      r = r.plus(h.multipliedBy(a0 | b0));
      a = a.dividedToIntegerBy(m);
      b = b.dividedToIntegerBy(m);
      h = h.multipliedBy(m);
    }
    r = r.plus(h.multipliedBy(a | b));
    return r;
  }
  $module.BitwiseXor = function(a, b) {
    let r = _dafny.ZERO;
    const m = _dafny.NUMBER_LIMIT;  // 2^53
    let h = _dafny.ONE;
    while (!a.isZero() && !b.isZero()) {
      let a0 = a.mod(m);
      let b0 = b.mod(m);
      r = r.plus(h.multipliedBy(a0 ^ b0));
      a = a.dividedToIntegerBy(m);
      b = b.dividedToIntegerBy(m);
      h = h.multipliedBy(m);
    }
    r = r.plus(h.multipliedBy(a | b));
    return r;
  }
  $module.BitwiseNot = function(a, bits) {
    let r = _dafny.ZERO;
    let h = _dafny.ONE;
    for (let i = 0; i < bits; i++) {
      let bit = a.mod(2);
      if (bit.isZero()) {
        r = r.plus(h);
      }
      a = a.dividedToIntegerBy(2);
      h = h.multipliedBy(2);
    }
    return r;
  }
  $module.Quantifier = function(vals, frall, pred) {
    for (let u of vals) {
      if (pred(u) !== frall) { return !frall; }
    }
    return frall;
  }
  $module.PlusChar = function(a, b) {
    return String.fromCharCode(a.charCodeAt(0) + b.charCodeAt(0));
  }
  $module.UnicodePlusChar = function(a, b) {
    return new _dafny.CodePoint(a.value + b.value);
  }
  $module.MinusChar = function(a, b) {
    return String.fromCharCode(a.charCodeAt(0) - b.charCodeAt(0));
  }
  $module.UnicodeMinusChar = function(a, b) {
    return new _dafny.CodePoint(a.value - b.value);
  }
  $module.AllBooleans = function*() {
    yield false;
    yield true;
  }
  $module.AllChars = function*() {
    for (let i = 0; i < 0x10000; i++) {
      yield String.fromCharCode(i);
    }
  }
  $module.AllUnicodeChars = function*() {
    for (let i = 0; i < 0xD800; i++) {
      yield new _dafny.CodePoint(i);
    }
    for (let i = 0xE0000; i < 0x110000; i++) {
      yield new _dafny.CodePoint(i);
    }
  }
  $module.AllIntegers = function*() {
    yield _dafny.ZERO;
    for (let j = _dafny.ONE;; j = j.plus(1)) {
      yield j;
      yield j.negated();
    }
  }
  $module.IntegerRange = function*(lo, hi) {
    if (lo === null) {
      while (true) {
        hi = hi.minus(1);
        yield hi;
      }
    } else if (hi === null) {
      while (true) {
        yield lo;
        lo = lo.plus(1);
      }
    } else {
      while (lo.isLessThan(hi)) {
        yield lo;
        lo = lo.plus(1);
      }
    }
  }
  $module.SingleValue = function*(v) {
    yield v;
  }
  $module.HaltException = class HaltException extends Error {
    constructor(message) {
      super(message)
    }
  }
  $module.HandleHaltExceptions = function(f) {
    try {
      f()
    } catch (e) {
      if (e instanceof _dafny.HaltException) {
        process.stdout.write("[Program halted] " + e.message + "\n")
        process.exitCode = 1
      } else {
        throw e
      }
    }
  }
  $module.FromMainArguments = function(args) {
    var a = [...args];
    a.splice(0, 2, args[0] + " " + args[1]);
    return a;
  }
  $module.UnicodeFromMainArguments = function(args) {
    return $module.FromMainArguments(args).map(_dafny.Seq.UnicodeFromString);
  }
  return $module;

  // What follows are routines private to the Dafny runtime
  function buildArray(initValue, ...dims) {
    if (dims.length === 0) {
      return initValue;
    } else {
      let a = Array(dims[0].toNumber());
      let b = Array.from(a, (x) => buildArray(initValue, ...dims.slice(1)));
      return b;
    }
  }
  function arrayElementsToString(a) {
    // like `a.join(", ")`, but calling _dafny.toString(x) on every element x instead of x.toString()
    let s = "";
    let sep = "";
    for (let x of a) {
      s += sep + _dafny.toString(x);
      sep = ", ";
    }
    return s;
  }
  function BigNumberGcd(a, b){  // gcd of two non-negative BigNumber's
    while (true) {
      if (a.isZero()) {
        return b;
      } else if (b.isZero()) {
        return a;
      }
      if (a.isLessThan(b)) {
        b = b.modulo(a);
      } else {
        a = a.modulo(b);
      }
    }
  }
})();
// Dafny program systemModulePopulator.dfy compiled into JavaScript
let _System = (function() {
  let $module = {};

  $module.nat = class nat {
    constructor () {
    }
    static get Default() {
      return _dafny.ZERO;
    }
    static _Is(__source) {
      let _0_x = (__source);
      return (_dafny.ZERO).isLessThanOrEqualTo(_0_x);
    }
  };

  return $module;
})(); // end of module _System
let Merkle = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Merkle._default";
    }
    _parentTraits() {
      return [];
    }
    static LeafH(H, d) {
      return (H)(_dafny.Seq.Concat(_dafny.Seq.of(0), d));
    };
    static NodeH(H, l, r) {
      return (H)(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(1), l), r));
    };
    static Pow2(j) {
      let _0___accumulator = _dafny.ONE;
      TAIL_CALL_START: while (true) {
        if ((j).isEqualTo(_dafny.ZERO)) {
          return (_dafny.ONE).multipliedBy(_0___accumulator);
        } else {
          _0___accumulator = (_0___accumulator).multipliedBy(new BigNumber(2));
          let _in0 = (j).minus(_dafny.ONE);
          j = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static SplitJ(n, j) {
      TAIL_CALL_START: while (true) {
        if (((new BigNumber(2)).multipliedBy(Merkle.__default.Pow2(j))).isLessThan(n)) {
          let _in0 = n;
          let _in1 = (j).plus(_dafny.ONE);
          n = _in0;
          j = _in1;
          continue TAIL_CALL_START;
        } else {
          return j;
        }
      }
    };
    static Split(n) {
      if ((n).isLessThan(new BigNumber(2))) {
        return _dafny.ONE;
      } else {
        return Merkle.__default.Pow2(Merkle.__default.SplitJ(n, _dafny.ZERO));
      }
    };
    static Root(H, ds) {
      if ((new BigNumber((ds).length)).isEqualTo(_dafny.ZERO)) {
        return (H)(_dafny.Seq.of());
      } else if ((new BigNumber((ds).length)).isEqualTo(_dafny.ONE)) {
        return Merkle.__default.LeafH(H, (ds)[_dafny.ZERO]);
      } else {
        let _0_k = Merkle.__default.Split(new BigNumber((ds).length));
        return Merkle.__default.NodeH(H, Merkle.__default.Root(H, (ds).slice(0, _0_k)), Merkle.__default.Root(H, (ds).slice(_0_k)));
      }
    };
    static Sides(p) {
      return _dafny.Seq.Create(new BigNumber((p).length), ((_0_p) => function (_1_i) {
        return ((_0_p)[_1_i]).dtor_side;
      })(p));
    };
    static Shape(idx, n) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((n).isEqualTo(_dafny.ONE)) {
          return _dafny.Seq.Concat(_dafny.Seq.of(), _0___accumulator);
        } else {
          let _1_k = Merkle.__default.Split(n);
          if ((idx).isLessThan(_1_k)) {
            _0___accumulator = _dafny.Seq.Concat(_dafny.Seq.of(Merkle.Side.create_Rt()), _0___accumulator);
            let _in0 = idx;
            let _in1 = _1_k;
            idx = _in0;
            n = _in1;
            continue TAIL_CALL_START;
          } else {
            _0___accumulator = _dafny.Seq.Concat(_dafny.Seq.of(Merkle.Side.create_Lt()), _0___accumulator);
            let _in2 = (idx).minus(_1_k);
            let _in3 = (n).minus(_1_k);
            idx = _in2;
            n = _in3;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static InclPath(H, ds, idx) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((ds).length)).isEqualTo(_dafny.ONE)) {
          return _dafny.Seq.Concat(_dafny.Seq.of(), _0___accumulator);
        } else {
          let _1_k = Merkle.__default.Split(new BigNumber((ds).length));
          if ((idx).isLessThan(_1_k)) {
            _0___accumulator = _dafny.Seq.Concat(_dafny.Seq.of(Merkle.Step.create_Step(Merkle.Side.create_Rt(), Merkle.__default.Root(H, (ds).slice(_1_k)))), _0___accumulator);
            let _in0 = H;
            let _in1 = (ds).slice(0, _1_k);
            let _in2 = idx;
            H = _in0;
            ds = _in1;
            idx = _in2;
            continue TAIL_CALL_START;
          } else {
            _0___accumulator = _dafny.Seq.Concat(_dafny.Seq.of(Merkle.Step.create_Step(Merkle.Side.create_Lt(), Merkle.__default.Root(H, (ds).slice(0, _1_k)))), _0___accumulator);
            let _in3 = H;
            let _in4 = (ds).slice(_1_k);
            let _in5 = (idx).minus(_1_k);
            H = _in3;
            ds = _in4;
            idx = _in5;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static IncStep(H, h, s) {
      if (_dafny.areEqual((s).dtor_side, Merkle.Side.create_Lt())) {
        return Merkle.__default.NodeH(H, (s).dtor_hash, h);
      } else {
        return Merkle.__default.NodeH(H, h, (s).dtor_hash);
      }
    };
    static IncFold(H, h, p) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((p).length)).isEqualTo(_dafny.ZERO)) {
          return h;
        } else {
          let _in0 = H;
          let _in1 = Merkle.__default.IncStep(H, h, (p)[_dafny.ZERO]);
          let _in2 = (p).slice(_dafny.ONE);
          H = _in0;
          h = _in1;
          p = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static VerifyInclusion(H, L, root, index, size, path, leaf) {
      return (((((_dafny.ONE).isLessThanOrEqualTo(size)) && (((_dafny.ZERO).isLessThanOrEqualTo(index)) && ((index).isLessThan(size)))) && (_dafny.areEqual(Merkle.__default.Sides(path), Merkle.__default.Shape(index, size)))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((path).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((path).length)))) || ((new BigNumber((((path)[_0_i]).dtor_hash).length)).isEqualTo(L));
      }))) && (_dafny.areEqual(Merkle.__default.IncFold(H, Merkle.__default.LeafH(H, leaf), path), root));
    };
    static IsPow2(m) {
      return ((_dafny.ONE).isLessThanOrEqualTo(m)) && (((m).isEqualTo(_dafny.ONE)) || ((((m).mod(new BigNumber(2))).isEqualTo(_dafny.ZERO)) && (Merkle.__default.IsPow2(_dafny.EuclideanDivision(m, new BigNumber(2))))));
    };
    static PreShift(fn, sn) {
      TAIL_CALL_START: while (true) {
        if (((fn).mod(new BigNumber(2))).isEqualTo(_dafny.ONE)) {
          let _in0 = _dafny.EuclideanDivision(fn, new BigNumber(2));
          let _in1 = _dafny.EuclideanDivision(sn, new BigNumber(2));
          fn = _in0;
          sn = _in1;
          continue TAIL_CALL_START;
        } else {
          return _dafny.Tuple.of(fn, sn);
        }
      }
    };
    static PreJ(fn) {
      let _0___accumulator = _dafny.ZERO;
      TAIL_CALL_START: while (true) {
        if (((fn).mod(new BigNumber(2))).isEqualTo(_dafny.ONE)) {
          _0___accumulator = (_0___accumulator).plus(_dafny.ONE);
          let _in0 = _dafny.EuclideanDivision(fn, new BigNumber(2));
          fn = _in0;
          continue TAIL_CALL_START;
        } else {
          return (_dafny.ZERO).plus(_0___accumulator);
        }
      }
    };
    static SkipEven(fn, sn) {
      TAIL_CALL_START: while (true) {
        if ((((fn).mod(new BigNumber(2))).isEqualTo(_dafny.ZERO)) && (!(fn).isEqualTo(_dafny.ZERO))) {
          let _in0 = _dafny.EuclideanDivision(fn, new BigNumber(2));
          let _in1 = _dafny.EuclideanDivision(sn, new BigNumber(2));
          fn = _in0;
          sn = _in1;
          continue TAIL_CALL_START;
        } else {
          return _dafny.Tuple.of(fn, sn);
        }
      }
    };
    static SkipJ(fn) {
      let _0___accumulator = _dafny.ZERO;
      TAIL_CALL_START: while (true) {
        if ((((fn).mod(new BigNumber(2))).isEqualTo(_dafny.ZERO)) && (!(fn).isEqualTo(_dafny.ZERO))) {
          _0___accumulator = (_0___accumulator).plus(_dafny.ONE);
          let _in0 = _dafny.EuclideanDivision(fn, new BigNumber(2));
          fn = _in0;
          continue TAIL_CALL_START;
        } else {
          return (_dafny.ZERO).plus(_0___accumulator);
        }
      }
    };
    static CLoop(H, L, fn, sn, fr, sr, p) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((p).length)).isEqualTo(_dafny.ZERO)) {
          if ((sn).isEqualTo(_dafny.ZERO)) {
            return Merkle.Option.create_Some(_dafny.Tuple.of(fr, sr));
          } else {
            return Merkle.Option.create_None();
          }
        } else if ((sn).isEqualTo(_dafny.ZERO)) {
          return Merkle.Option.create_None();
        } else if (!(new BigNumber(((p)[_dafny.ZERO]).length)).isEqualTo(L)) {
          return Merkle.Option.create_None();
        } else if ((((fn).mod(new BigNumber(2))).isEqualTo(_dafny.ONE)) || ((fn).isEqualTo(sn))) {
          let _0_se = Merkle.__default.SkipEven(fn, sn);
          let _in0 = H;
          let _in1 = L;
          let _in2 = _dafny.EuclideanDivision((_0_se)[0], new BigNumber(2));
          let _in3 = _dafny.EuclideanDivision((_0_se)[1], new BigNumber(2));
          let _in4 = Merkle.__default.NodeH(H, (p)[_dafny.ZERO], fr);
          let _in5 = Merkle.__default.NodeH(H, (p)[_dafny.ZERO], sr);
          let _in6 = (p).slice(_dafny.ONE);
          H = _in0;
          L = _in1;
          fn = _in2;
          sn = _in3;
          fr = _in4;
          sr = _in5;
          p = _in6;
          continue TAIL_CALL_START;
        } else {
          let _in7 = H;
          let _in8 = L;
          let _in9 = _dafny.EuclideanDivision(fn, new BigNumber(2));
          let _in10 = _dafny.EuclideanDivision(sn, new BigNumber(2));
          let _in11 = fr;
          let _in12 = Merkle.__default.NodeH(H, sr, (p)[_dafny.ZERO]);
          let _in13 = (p).slice(_dafny.ONE);
          H = _in7;
          L = _in8;
          fn = _in9;
          sn = _in10;
          fr = _in11;
          sr = _in12;
          p = _in13;
          continue TAIL_CALL_START;
        }
      }
    };
    static VerifyConsistency(H, L, oldRoot, newRoot, m, n, p) {
      if (((m).isLessThan(_dafny.ZERO)) || ((n).isLessThan(m))) {
        return false;
      } else if ((m).isEqualTo(_dafny.ZERO)) {
        return (((new BigNumber((p).length)).isEqualTo(_dafny.ZERO)) && (_dafny.areEqual(oldRoot, (H)(_dafny.Seq.of())))) && (!((n).isEqualTo(_dafny.ZERO)) || (_dafny.areEqual(newRoot, (H)(_dafny.Seq.of()))));
      } else if ((m).isEqualTo(n)) {
        return ((new BigNumber((p).length)).isEqualTo(_dafny.ZERO)) && (_dafny.areEqual(oldRoot, newRoot));
      } else {
        return Merkle.__default.VerMid(H, L, oldRoot, newRoot, m, n, p);
      }
    };
    static VerMid(H, L, oldRoot, newRoot, m, n, p) {
      let _pat_let_tv0 = H;
      let _pat_let_tv1 = L;
      let _pat_let_tv2 = oldRoot;
      let _pat_let_tv3 = newRoot;
      let _0_path = ((Merkle.__default.IsPow2(m)) ? (_dafny.Seq.Concat(_dafny.Seq.of(oldRoot), p)) : (p));
      return (((((_dafny.ONE).isLessThanOrEqualTo(new BigNumber((_0_path).length))) && ((new BigNumber((oldRoot).length)).isEqualTo(L))) && ((new BigNumber((newRoot).length)).isEqualTo(L))) && ((new BigNumber(((_0_path)[_dafny.ZERO]).length)).isEqualTo(L))) && (function (_pat_let0_0) {
        return function (_1_ps) {
          return function (_pat_let1_0) {
            return function (_2_r) {
              return (((_2_r).is_Some) && (_dafny.areEqual(((_2_r).dtor_v)[0], _pat_let_tv2))) && (_dafny.areEqual(((_2_r).dtor_v)[1], _pat_let_tv3));
            }(_pat_let1_0);
          }(Merkle.__default.CLoop(_pat_let_tv0, _pat_let_tv1, (_1_ps)[0], (_1_ps)[1], (_0_path)[_dafny.ZERO], (_0_path)[_dafny.ZERO], (_0_path).slice(_dafny.ONE)));
        }(_pat_let0_0);
      }(Merkle.__default.PreShift((m).minus(_dafny.ONE), (n).minus(_dafny.ONE))));
    };
    static Mn(a, b) {
      if ((a).isLessThan(b)) {
        return a;
      } else {
        return b;
      }
    };
    static NB(H, ds, l, j) {
      let _0_a = (j).multipliedBy(Merkle.__default.Pow2(l));
      let _1_b = Merkle.__default.Mn(((j).plus(_dafny.ONE)).multipliedBy(Merkle.__default.Pow2(l)), new BigNumber((ds).length));
      if ((_0_a).isLessThan(_1_b)) {
        return Merkle.__default.Root(H, (ds).slice(_0_a, _1_b));
      } else {
        return (H)(_dafny.Seq.of());
      }
    };
    static OP(H, ds, m, l, j) {
      let _0_a = (j).multipliedBy(Merkle.__default.Pow2(l));
      if (((_0_a).isLessThan(m)) && ((m).isLessThanOrEqualTo(new BigNumber((ds).length)))) {
        return Merkle.__default.Root(H, (ds).slice(_0_a, m));
      } else {
        return (H)(_dafny.Seq.of());
      }
    };
    static HL(H, ds, l, fn, sn) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((sn).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else if ((((fn).mod(new BigNumber(2))).isEqualTo(_dafny.ONE)) || ((fn).isEqualTo(sn))) {
          let _1_se = Merkle.__default.SkipEven(fn, sn);
          let _2_j = Merkle.__default.SkipJ(fn);
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(Merkle.__default.NB(H, ds, (l).plus(_2_j), (((_dafny.ONE).isLessThanOrEqualTo((_1_se)[0])) ? (((_1_se)[0]).minus(_dafny.ONE)) : (_dafny.ZERO)))));
          let _in0 = H;
          let _in1 = ds;
          let _in2 = ((l).plus(_2_j)).plus(_dafny.ONE);
          let _in3 = _dafny.EuclideanDivision((_1_se)[0], new BigNumber(2));
          let _in4 = _dafny.EuclideanDivision((_1_se)[1], new BigNumber(2));
          H = _in0;
          ds = _in1;
          l = _in2;
          fn = _in3;
          sn = _in4;
          continue TAIL_CALL_START;
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(Merkle.__default.NB(H, ds, l, (fn).plus(_dafny.ONE))));
          let _in5 = H;
          let _in6 = ds;
          let _in7 = (l).plus(_dafny.ONE);
          let _in8 = _dafny.EuclideanDivision(fn, new BigNumber(2));
          let _in9 = _dafny.EuclideanDivision(sn, new BigNumber(2));
          H = _in5;
          ds = _in6;
          l = _in7;
          fn = _in8;
          sn = _in9;
          continue TAIL_CALL_START;
        }
      }
    };
    static HonestCons(H, ds, m) {
      if (((m).isLessThanOrEqualTo(_dafny.ZERO)) || ((new BigNumber((ds).length)).isLessThanOrEqualTo(m))) {
        return _dafny.Seq.of();
      } else {
        let _0_ps = Merkle.__default.PreShift((m).minus(_dafny.ONE), (new BigNumber((ds).length)).minus(_dafny.ONE));
        let _1_t = Merkle.__default.PreJ((m).minus(_dafny.ONE));
        return _dafny.Seq.Concat(((Merkle.__default.IsPow2(m)) ? (_dafny.Seq.of()) : (_dafny.Seq.of(Merkle.__default.NB(H, ds, _1_t, (_0_ps)[0])))), Merkle.__default.HL(H, ds, _1_t, (_0_ps)[0], (_0_ps)[1]));
      }
    };
    static Bits(x) {
      let _0___accumulator = _dafny.ZERO;
      TAIL_CALL_START: while (true) {
        if ((x).isEqualTo(_dafny.ZERO)) {
          return (_dafny.ZERO).plus(_0___accumulator);
        } else {
          _0___accumulator = (_0___accumulator).plus(_dafny.ONE);
          let _in0 = _dafny.EuclideanDivision(x, new BigNumber(2));
          x = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static InclusionRoot(H, L, index, size, path, leaf) {
      if (((((_dafny.ONE).isLessThanOrEqualTo(size)) && (((_dafny.ZERO).isLessThanOrEqualTo(index)) && ((index).isLessThan(size)))) && (_dafny.areEqual(Merkle.__default.Sides(path), Merkle.__default.Shape(index, size)))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((path).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((path).length)))) || ((new BigNumber((((path)[_0_i]).dtor_hash).length)).isEqualTo(L));
      }))) {
        return Merkle.Option.create_Some(Merkle.__default.IncFold(H, Merkle.__default.LeafH(H, leaf), path));
      } else {
        return Merkle.Option.create_None();
      }
    };
    static SubProof(H, ds, m, b) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((m).isEqualTo(new BigNumber((ds).length))) {
          if (b) {
            return _dafny.Seq.Concat(_dafny.Seq.of(), _0___accumulator);
          } else {
            return _dafny.Seq.Concat(_dafny.Seq.of(Merkle.__default.Root(H, ds)), _0___accumulator);
          }
        } else {
          let _1_k = Merkle.__default.Split(new BigNumber((ds).length));
          if ((m).isLessThanOrEqualTo(_1_k)) {
            _0___accumulator = _dafny.Seq.Concat(_dafny.Seq.of(Merkle.__default.Root(H, (ds).slice(_1_k))), _0___accumulator);
            let _in0 = H;
            let _in1 = (ds).slice(0, _1_k);
            let _in2 = m;
            let _in3 = b;
            H = _in0;
            ds = _in1;
            m = _in2;
            b = _in3;
            continue TAIL_CALL_START;
          } else {
            _0___accumulator = _dafny.Seq.Concat(_dafny.Seq.of(Merkle.__default.Root(H, (ds).slice(0, _1_k))), _0___accumulator);
            let _in4 = H;
            let _in5 = (ds).slice(_1_k);
            let _in6 = (m).minus(_1_k);
            let _in7 = false;
            H = _in4;
            ds = _in5;
            m = _in6;
            b = _in7;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static SubModel(H, ds, m, b) {
      if ((m).isEqualTo(new BigNumber((ds).length))) {
        if (b) {
          return _dafny.Seq.of();
        } else {
          return _dafny.Seq.of(Merkle.__default.Root(H, ds));
        }
      } else {
        let _0_ps = Merkle.__default.PreShift((m).minus(_dafny.ONE), (new BigNumber((ds).length)).minus(_dafny.ONE));
        let _1_t = Merkle.__default.PreJ((m).minus(_dafny.ONE));
        return _dafny.Seq.Concat((((b) && (Merkle.__default.IsPow2(m))) ? (_dafny.Seq.of()) : (_dafny.Seq.of(Merkle.__default.NB(H, ds, _1_t, (_0_ps)[0])))), Merkle.__default.HL(H, ds, _1_t, (_0_ps)[0], (_0_ps)[1]));
      }
    };
    static ExpLen(fn, sn) {
      let _0___accumulator = _dafny.ZERO;
      TAIL_CALL_START: while (true) {
        if ((sn).isEqualTo(_dafny.ZERO)) {
          return (_dafny.ZERO).plus(_0___accumulator);
        } else if ((((fn).mod(new BigNumber(2))).isEqualTo(_dafny.ONE)) || ((fn).isEqualTo(sn))) {
          let _1_se = Merkle.__default.SkipEven(fn, sn);
          _0___accumulator = (_0___accumulator).plus(_dafny.ONE);
          let _in0 = _dafny.EuclideanDivision((_1_se)[0], new BigNumber(2));
          let _in1 = _dafny.EuclideanDivision((_1_se)[1], new BigNumber(2));
          fn = _in0;
          sn = _in1;
          continue TAIL_CALL_START;
        } else {
          _0___accumulator = (_0___accumulator).plus(_dafny.ONE);
          let _in2 = _dafny.EuclideanDivision(fn, new BigNumber(2));
          let _in3 = _dafny.EuclideanDivision(sn, new BigNumber(2));
          fn = _in2;
          sn = _in3;
          continue TAIL_CALL_START;
        }
      }
    };
    static ConsLen(m, n) {
      let _0_ps = Merkle.__default.PreShift((m).minus(_dafny.ONE), (n).minus(_dafny.ONE));
      return ((Merkle.__default.ExpLen((_0_ps)[0], (_0_ps)[1])).plus(_dafny.ONE)).minus(((Merkle.__default.IsPow2(m)) ? (_dafny.ONE) : (_dafny.ZERO)));
    };
  };

  $module._$$_byte = class _$$_byte {
    constructor () {
    }
    _parentTraits() {
      return [];
    }
    static *IntegerRange(lo, hi) {
      while (lo.isLessThan(hi)) {
        yield lo.toNumber();
        lo = lo.plus(1);
      }
    }
    static get Default() {
      return 0;
    }
    static _Is(__source) {
      let _0_b = new BigNumber(__source);
      return ((_dafny.ZERO).isLessThanOrEqualTo(_0_b)) && ((_0_b).isLessThan(new BigNumber(256)));
    }
  };

  $module.Option = class Option {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_None() {
      let $dt = new Option(0);
      return $dt;
    }
    static create_Some(v) {
      let $dt = new Option(1);
      $dt.v = v;
      return $dt;
    }
    get is_None() { return this.$tag === 0; }
    get is_Some() { return this.$tag === 1; }
    get dtor_v() { return this.v; }
    toString() {
      if (this.$tag === 0) {
        return "Merkle.Option.None";
      } else if (this.$tag === 1) {
        return "Merkle.Option.Some" + "(" + _dafny.toString(this.v) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.v, other.v);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Merkle.Option.create_None();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Option.Default();
        }
      };
    }
  }

  $module.Side = class Side {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Lt() {
      let $dt = new Side(0);
      return $dt;
    }
    static create_Rt() {
      let $dt = new Side(1);
      return $dt;
    }
    get is_Lt() { return this.$tag === 0; }
    get is_Rt() { return this.$tag === 1; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield Side.create_Lt();
      yield Side.create_Rt();
    }
    toString() {
      if (this.$tag === 0) {
        return "Merkle.Side.Lt";
      } else if (this.$tag === 1) {
        return "Merkle.Side.Rt";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0;
      } else if (this.$tag === 1) {
        return other.$tag === 1;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Merkle.Side.create_Lt();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Side.Default();
        }
      };
    }
  }

  $module.Step = class Step {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Step(side, hash) {
      let $dt = new Step(0);
      $dt.side = side;
      $dt.hash = hash;
      return $dt;
    }
    get is_Step() { return this.$tag === 0; }
    get dtor_side() { return this.side; }
    get dtor_hash() { return this.hash; }
    toString() {
      if (this.$tag === 0) {
        return "Merkle.Step.Step" + "(" + _dafny.toString(this.side) + ", " + _dafny.toString(this.hash) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.side, other.side) && _dafny.areEqual(this.hash, other.hash);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Merkle.Step.create_Step(Merkle.Side.Default(), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Step.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module Merkle
let _module = (function() {
  let $module = {};

  return $module;
})(); // end of module _module

// ---- exports (appended by formal/dafny/build-ext.sh) ----
module.exports = { _dafny, Merkle };
