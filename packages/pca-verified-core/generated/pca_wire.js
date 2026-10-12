// Dafny program Wire.dfy compiled into JavaScript
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
let Utf = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Utf._default";
    }
    _parentTraits() {
      return [];
    }
    static IsUnit(x) {
      return ((_dafny.ZERO).isLessThanOrEqualTo(x)) && ((x).isLessThan(new BigNumber(65536)));
    };
    static IsHigh(x) {
      return ((new BigNumber(55296)).isLessThanOrEqualTo(x)) && ((x).isLessThanOrEqualTo(new BigNumber(56319)));
    };
    static IsLow(x) {
      return ((new BigNumber(56320)).isLessThanOrEqualTo(x)) && ((x).isLessThanOrEqualTo(new BigNumber(57343)));
    };
    static Valid16From(s, i) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((s).length)).isLessThanOrEqualTo(i)) {
          return true;
        } else if (!(Utf.__default.IsUnit((s)[i]))) {
          return false;
        } else if (Utf.__default.IsHigh((s)[i])) {
          if (((((i).plus(_dafny.ONE)).isLessThan(new BigNumber((s).length))) && (Utf.__default.IsLow((s)[(i).plus(_dafny.ONE)]))) && (Utf.__default.IsUnit((s)[(i).plus(_dafny.ONE)]))) {
            let _in0 = s;
            let _in1 = (i).plus(new BigNumber(2));
            s = _in0;
            i = _in1;
            continue TAIL_CALL_START;
          } else {
            return false;
          }
        } else if (Utf.__default.IsLow((s)[i])) {
          return false;
        } else {
          let _in2 = s;
          let _in3 = (i).plus(_dafny.ONE);
          s = _in2;
          i = _in3;
          continue TAIL_CALL_START;
        }
      }
    };
    static Valid16(s) {
      return Utf.__default.Valid16From(s, _dafny.ZERO);
    };
    static Cps(s) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((s).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else if (((Utf.__default.IsHigh((s)[_dafny.ZERO])) && ((new BigNumber(2)).isLessThanOrEqualTo(new BigNumber((s).length)))) && (Utf.__default.IsLow((s)[_dafny.ONE]))) {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(((new BigNumber(65536)).plus((((s)[_dafny.ZERO]).minus(new BigNumber(55296))).multipliedBy(new BigNumber(1024)))).plus(((s)[_dafny.ONE]).minus(new BigNumber(56320)))));
          let _in0 = (s).slice(new BigNumber(2));
          s = _in0;
          continue TAIL_CALL_START;
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of((s)[_dafny.ZERO]));
          let _in1 = (s).slice(_dafny.ONE);
          s = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static ValidCp(c) {
      return (((_dafny.ZERO).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(1114111)))) && (!(((new BigNumber(55296)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(57343)))));
    };
    static AllCp(c) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((c).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((c).length)))) || (Utf.__default.ValidCp((c)[_0_i]));
      });
    };
    static Enc8(c) {
      if ((c).isLessThan(new BigNumber(128))) {
        return _dafny.Seq.of(c);
      } else if ((c).isLessThan(new BigNumber(2048))) {
        return _dafny.Seq.of((new BigNumber(192)).plus(_dafny.EuclideanDivision(c, new BigNumber(64))), (new BigNumber(128)).plus((c).mod(new BigNumber(64))));
      } else if ((c).isLessThan(new BigNumber(65536))) {
        return _dafny.Seq.of((new BigNumber(224)).plus(_dafny.EuclideanDivision(c, new BigNumber(4096))), (new BigNumber(128)).plus((_dafny.EuclideanDivision(c, new BigNumber(64))).mod(new BigNumber(64))), (new BigNumber(128)).plus((c).mod(new BigNumber(64))));
      } else {
        return _dafny.Seq.of((new BigNumber(240)).plus(_dafny.EuclideanDivision(c, new BigNumber(262144))), (new BigNumber(128)).plus((_dafny.EuclideanDivision(c, new BigNumber(4096))).mod(new BigNumber(64))), (new BigNumber(128)).plus((_dafny.EuclideanDivision(c, new BigNumber(64))).mod(new BigNumber(64))), (new BigNumber(128)).plus((c).mod(new BigNumber(64))));
      }
    };
    static Utf8(cs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((cs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, Utf.__default.Enc8((cs)[_dafny.ZERO]));
          let _in0 = (cs).slice(_dafny.ONE);
          cs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static IsPrefix(p, q) {
      return ((new BigNumber((p).length)).isLessThanOrEqualTo(new BigNumber((q).length))) && (_dafny.areEqual((q).slice(0, new BigNumber((p).length)), p));
    };
    static LexLess(a, b) {
      return ((_dafny.ZERO).isLessThan(new BigNumber((b).length))) && ((((new BigNumber((a).length)).isEqualTo(_dafny.ZERO)) || (((a)[_dafny.ZERO]).isLessThan((b)[_dafny.ZERO]))) || ((((a)[_dafny.ZERO]).isEqualTo((b)[_dafny.ZERO])) && (Utf.__default.LexLess((a).slice(_dafny.ONE), (b).slice(_dafny.ONE)))));
    };
    static Utf8Of16(s) {
      return Utf.__default.Utf8(Utf.__default.Cps(s));
    };
    static KLess(a, b) {
      return Utf.__default.LexLess(Utf.__default.Cps(a), Utf.__default.Cps(b));
    };
    static Utf8LenSpec(s) {
      let _0___accumulator = _dafny.ZERO;
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((s).length)).isEqualTo(_dafny.ZERO)) {
          return (_dafny.ZERO).plus(_0___accumulator);
        } else if (((Utf.__default.IsHigh((s)[_dafny.ZERO])) && ((new BigNumber(2)).isLessThanOrEqualTo(new BigNumber((s).length)))) && (Utf.__default.IsLow((s)[_dafny.ONE]))) {
          _0___accumulator = (_0___accumulator).plus(new BigNumber(4));
          let _in0 = (s).slice(new BigNumber(2));
          s = _in0;
          continue TAIL_CALL_START;
        } else {
          _0___accumulator = (_0___accumulator).plus(((((s)[_dafny.ZERO]).isLessThan(new BigNumber(128))) ? (_dafny.ONE) : (((((s)[_dafny.ZERO]).isLessThan(new BigNumber(2048))) ? (new BigNumber(2)) : (new BigNumber(3))))));
          let _in1 = (s).slice(_dafny.ONE);
          s = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static Utf8LenFrom(s, i, acc) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((s).length)).isLessThanOrEqualTo(i)) {
          return acc;
        } else if (((Utf.__default.IsHigh((s)[i])) && (((i).plus(_dafny.ONE)).isLessThan(new BigNumber((s).length)))) && (Utf.__default.IsLow((s)[(i).plus(_dafny.ONE)]))) {
          let _in0 = s;
          let _in1 = (i).plus(new BigNumber(2));
          let _in2 = (acc).plus(new BigNumber(4));
          s = _in0;
          i = _in1;
          acc = _in2;
          continue TAIL_CALL_START;
        } else {
          let _in3 = s;
          let _in4 = (i).plus(_dafny.ONE);
          let _in5 = (acc).plus(((((s)[i]).isLessThan(new BigNumber(128))) ? (_dafny.ONE) : (((((s)[i]).isLessThan(new BigNumber(2048))) ? (new BigNumber(2)) : (new BigNumber(3))))));
          s = _in3;
          i = _in4;
          acc = _in5;
          continue TAIL_CALL_START;
        }
      }
    };
    static Utf8LenLoose(s) {
      return Utf.__default.Utf8LenFrom(s, _dafny.ZERO, _dafny.ZERO);
    };
  };
  return $module;
})(); // end of module Utf
let B64 = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "B64._default";
    }
    _parentTraits() {
      return [];
    }
    static IsByte(x) {
      return ((_dafny.ZERO).isLessThanOrEqualTo(x)) && ((x).isLessThan(new BigNumber(256)));
    };
    static AllBytes(b) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((b).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((b).length)))) || (B64.__default.IsByte((b)[_0_i]));
      });
    };
    static Ch(v) {
      if ((v).isLessThan(new BigNumber(26))) {
        return (new BigNumber(65)).plus(v);
      } else if ((v).isLessThan(new BigNumber(52))) {
        return (new BigNumber(97)).plus((v).minus(new BigNumber(26)));
      } else if ((v).isLessThan(new BigNumber(62))) {
        return (new BigNumber(48)).plus((v).minus(new BigNumber(52)));
      } else if ((v).isEqualTo(new BigNumber(62))) {
        return new BigNumber(45);
      } else {
        return new BigNumber(95);
      }
    };
    static Val(c) {
      if (((new BigNumber(65)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(90)))) {
        return (c).minus(new BigNumber(65));
      } else if (((new BigNumber(97)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(122)))) {
        return ((c).minus(new BigNumber(97))).plus(new BigNumber(26));
      } else if (((new BigNumber(48)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(57)))) {
        return ((c).minus(new BigNumber(48))).plus(new BigNumber(52));
      } else if ((c).isEqualTo(new BigNumber(45))) {
        return new BigNumber(62);
      } else if ((c).isEqualTo(new BigNumber(95))) {
        return new BigNumber(63);
      } else {
        return new BigNumber(-1);
      }
    };
    static Enc(b) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((b).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else if ((new BigNumber((b).length)).isEqualTo(_dafny.ONE)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(B64.__default.Ch(_dafny.EuclideanDivision((b)[_dafny.ZERO], new BigNumber(4))), B64.__default.Ch((((b)[_dafny.ZERO]).mod(new BigNumber(4))).multipliedBy(new BigNumber(16)))));
        } else if ((new BigNumber((b).length)).isEqualTo(new BigNumber(2))) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(B64.__default.Ch(_dafny.EuclideanDivision((b)[_dafny.ZERO], new BigNumber(4))), B64.__default.Ch(((((b)[_dafny.ZERO]).mod(new BigNumber(4))).multipliedBy(new BigNumber(16))).plus(_dafny.EuclideanDivision((b)[_dafny.ONE], new BigNumber(16)))), B64.__default.Ch((((b)[_dafny.ONE]).mod(new BigNumber(16))).multipliedBy(new BigNumber(4)))));
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(B64.__default.Ch(_dafny.EuclideanDivision((b)[_dafny.ZERO], new BigNumber(4))), B64.__default.Ch(((((b)[_dafny.ZERO]).mod(new BigNumber(4))).multipliedBy(new BigNumber(16))).plus(_dafny.EuclideanDivision((b)[_dafny.ONE], new BigNumber(16)))), B64.__default.Ch(((((b)[_dafny.ONE]).mod(new BigNumber(16))).multipliedBy(new BigNumber(4))).plus(_dafny.EuclideanDivision((b)[new BigNumber(2)], new BigNumber(64)))), B64.__default.Ch(((b)[new BigNumber(2)]).mod(new BigNumber(64)))));
          let _in0 = (b).slice(new BigNumber(3));
          b = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static Dec(s) {
      if ((new BigNumber((s).length)).isEqualTo(_dafny.ZERO)) {
        return B64.Option.create_Some(_dafny.Seq.of());
      } else if ((new BigNumber((s).length)).isEqualTo(_dafny.ONE)) {
        return B64.Option.create_None();
      } else if ((new BigNumber((s).length)).isEqualTo(new BigNumber(2))) {
        if ((((_dafny.ZERO).isLessThanOrEqualTo(B64.__default.Val((s)[_dafny.ZERO]))) && ((_dafny.ZERO).isLessThanOrEqualTo(B64.__default.Val((s)[_dafny.ONE])))) && (((B64.__default.Val((s)[_dafny.ONE])).mod(new BigNumber(16))).isEqualTo(_dafny.ZERO))) {
          return B64.Option.create_Some(_dafny.Seq.of(((B64.__default.Val((s)[_dafny.ZERO])).multipliedBy(new BigNumber(4))).plus(_dafny.EuclideanDivision(B64.__default.Val((s)[_dafny.ONE]), new BigNumber(16)))));
        } else {
          return B64.Option.create_None();
        }
      } else if ((new BigNumber((s).length)).isEqualTo(new BigNumber(3))) {
        if (((((_dafny.ZERO).isLessThanOrEqualTo(B64.__default.Val((s)[_dafny.ZERO]))) && ((_dafny.ZERO).isLessThanOrEqualTo(B64.__default.Val((s)[_dafny.ONE])))) && ((_dafny.ZERO).isLessThanOrEqualTo(B64.__default.Val((s)[new BigNumber(2)])))) && (((B64.__default.Val((s)[new BigNumber(2)])).mod(new BigNumber(4))).isEqualTo(_dafny.ZERO))) {
          return B64.Option.create_Some(_dafny.Seq.of(((B64.__default.Val((s)[_dafny.ZERO])).multipliedBy(new BigNumber(4))).plus(_dafny.EuclideanDivision(B64.__default.Val((s)[_dafny.ONE]), new BigNumber(16))), (((B64.__default.Val((s)[_dafny.ONE])).mod(new BigNumber(16))).multipliedBy(new BigNumber(16))).plus(_dafny.EuclideanDivision(B64.__default.Val((s)[new BigNumber(2)]), new BigNumber(4)))));
        } else {
          return B64.Option.create_None();
        }
      } else if (((((_dafny.ZERO).isLessThanOrEqualTo(B64.__default.Val((s)[_dafny.ZERO]))) && ((_dafny.ZERO).isLessThanOrEqualTo(B64.__default.Val((s)[_dafny.ONE])))) && ((_dafny.ZERO).isLessThanOrEqualTo(B64.__default.Val((s)[new BigNumber(2)])))) && ((_dafny.ZERO).isLessThanOrEqualTo(B64.__default.Val((s)[new BigNumber(3)])))) {
        let _source0 = B64.__default.Dec((s).slice(new BigNumber(4)));
        {
          if (_source0.is_None) {
            return B64.Option.create_None();
          }
        }
        {
          let _0_rest = (_source0).v;
          return B64.Option.create_Some(_dafny.Seq.Concat(_dafny.Seq.of(((B64.__default.Val((s)[_dafny.ZERO])).multipliedBy(new BigNumber(4))).plus(_dafny.EuclideanDivision(B64.__default.Val((s)[_dafny.ONE]), new BigNumber(16))), (((B64.__default.Val((s)[_dafny.ONE])).mod(new BigNumber(16))).multipliedBy(new BigNumber(16))).plus(_dafny.EuclideanDivision(B64.__default.Val((s)[new BigNumber(2)]), new BigNumber(4))), (((B64.__default.Val((s)[new BigNumber(2)])).mod(new BigNumber(4))).multipliedBy(new BigNumber(64))).plus(B64.__default.Val((s)[new BigNumber(3)]))), _0_rest));
        }
      } else {
        return B64.Option.create_None();
      }
    };
    static EncLen(n) {
      return ((_dafny.EuclideanDivision(n, new BigNumber(3))).multipliedBy(new BigNumber(4))).plus(((((n).mod(new BigNumber(3))).isEqualTo(_dafny.ZERO)) ? (_dafny.ZERO) : (((n).mod(new BigNumber(3))).plus(_dafny.ONE))));
    };
    static DecodeStrict(s, len) {
      if (((len).is_Some) && ((((len).dtor_v).isLessThan(_dafny.ZERO)) || (!(new BigNumber((s).length)).isEqualTo(B64.__default.EncLen((len).dtor_v))))) {
        return B64.Option.create_None();
      } else {
        let _source0 = B64.__default.Dec(s);
        {
          if (_source0.is_None) {
            return B64.Option.create_None();
          }
        }
        {
          let _0_b = (_source0).v;
          if (((len).is_Some) && (!(new BigNumber((_0_b).length)).isEqualTo((len).dtor_v))) {
            return B64.Option.create_None();
          } else {
            return B64.Option.create_Some(_0_b);
          }
        }
      }
    };
    static HexCh(v) {
      if ((v).isLessThan(new BigNumber(10))) {
        return (new BigNumber(48)).plus(v);
      } else {
        return (new BigNumber(97)).plus((v).minus(new BigNumber(10)));
      }
    };
    static HexVal(c) {
      if (((new BigNumber(48)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(57)))) {
        return (c).minus(new BigNumber(48));
      } else if (((new BigNumber(97)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(102)))) {
        return ((c).minus(new BigNumber(97))).plus(new BigNumber(10));
      } else {
        return new BigNumber(-1);
      }
    };
    static HexEnc(b) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((b).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(B64.__default.HexCh(_dafny.EuclideanDivision((b)[_dafny.ZERO], new BigNumber(16))), B64.__default.HexCh(((b)[_dafny.ZERO]).mod(new BigNumber(16)))));
          let _in0 = (b).slice(_dafny.ONE);
          b = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static HexDec(s) {
      if ((new BigNumber((s).length)).isEqualTo(_dafny.ZERO)) {
        return B64.Option.create_Some(_dafny.Seq.of());
      } else if ((((new BigNumber((s).length)).isEqualTo(_dafny.ONE)) || ((B64.__default.HexVal((s)[_dafny.ZERO])).isLessThan(_dafny.ZERO))) || ((B64.__default.HexVal((s)[_dafny.ONE])).isLessThan(_dafny.ZERO))) {
        return B64.Option.create_None();
      } else {
        let _source0 = B64.__default.HexDec((s).slice(new BigNumber(2)));
        {
          if (_source0.is_None) {
            return B64.Option.create_None();
          }
        }
        {
          let _0_r = (_source0).v;
          return B64.Option.create_Some(_dafny.Seq.Concat(_dafny.Seq.of(((B64.__default.HexVal((s)[_dafny.ZERO])).multipliedBy(new BigNumber(16))).plus(B64.__default.HexVal((s)[_dafny.ONE]))), _0_r));
        }
      }
    };
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
        return "B64.Option.None";
      } else if (this.$tag === 1) {
        return "B64.Option.Some" + "(" + _dafny.toString(this.v) + ")";
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
      return B64.Option.create_None();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Option.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module B64
let Json = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Json._default";
    }
    _parentTraits() {
      return [];
    }
    static IsDig(c) {
      return ((new BigNumber(48)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(57)));
    };
    static AllDig(d) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((d).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((d).length)))) || (Json.__default.IsDig((d)[_0_i]));
      });
    };
    static Dig(n) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((n).isLessThan(new BigNumber(10))) {
          return _dafny.Seq.Concat(_dafny.Seq.of((new BigNumber(48)).plus(n)), _0___accumulator);
        } else {
          _0___accumulator = _dafny.Seq.Concat(_dafny.Seq.of((new BigNumber(48)).plus((n).mod(new BigNumber(10)))), _0___accumulator);
          let _in0 = _dafny.EuclideanDivision(n, new BigNumber(10));
          n = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static ValSeq(d) {
      if ((new BigNumber((d).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.ZERO;
      } else {
        return ((Json.__default.ValSeq((d).slice(0, (new BigNumber((d).length)).minus(_dafny.ONE)))).multipliedBy(new BigNumber(10))).plus(((d)[(new BigNumber((d).length)).minus(_dafny.ONE)]).minus(new BigNumber(48)));
      }
    };
    static FrTxt(fr) {
      return _dafny.Seq.Create(new BigNumber((fr).length), ((_0_fr) => function (_1_i) {
        return (new BigNumber(48)).plus((_0_fr)[_1_i]);
      })(fr));
    };
    static FrOf(t, a, b) {
      return _dafny.Seq.Create((b).minus(a), ((_0_t, _1_a, _2_b) => function (_3_i) {
        return ((_0_t)[(_1_a).plus(_3_i)]).minus(new BigNumber(48));
      })(t, a, b));
    };
    static Digits09(f) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((f).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((f).length)))) || (((_dafny.ZERO).isLessThanOrEqualTo((f)[_0_i])) && (((f)[_0_i]).isLessThanOrEqualTo(new BigNumber(9))));
      });
    };
    static LeadZeros(f) {
      let _0___accumulator = _dafny.ZERO;
      TAIL_CALL_START: while (true) {
        if (((_dafny.ZERO).isLessThan(new BigNumber((f).length))) && (((f)[_dafny.ZERO]).isEqualTo(_dafny.ZERO))) {
          _0___accumulator = (_0___accumulator).plus(_dafny.ONE);
          let _in0 = (f).slice(_dafny.ONE);
          f = _in0;
          continue TAIL_CALL_START;
        } else {
          return (_dafny.ZERO).plus(_0___accumulator);
        }
      }
    };
    static Sig(ip, fr) {
      if ((_dafny.ZERO).isLessThan(ip)) {
        return (new BigNumber((Json.__default.Dig(ip)).length)).plus(new BigNumber((fr).length));
      } else {
        return (new BigNumber((fr).length)).minus(Json.__default.LeadZeros(fr));
      }
    };
    static MagOk(ip, fr) {
      return ((_dafny.ZERO).isLessThan(ip)) || (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(6)), false, function (_exists_var_0) {
        let _0_i = _exists_var_0;
        return ((((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber(6)))) && ((_0_i).isLessThan(new BigNumber((fr).length)))) && (!((fr)[_0_i]).isEqualTo(_dafny.ZERO));
      }));
    };
    static ValidDec(neg, ip, fr) {
      return ((((((_dafny.ZERO).isLessThanOrEqualTo(ip)) && ((_dafny.ONE).isLessThanOrEqualTo(new BigNumber((fr).length)))) && (Json.__default.Digits09(fr))) && (!((fr)[(new BigNumber((fr).length)).minus(_dafny.ONE)]).isEqualTo(_dafny.ZERO))) && ((Json.__default.Sig(ip, fr)).isLessThanOrEqualTo(new BigNumber(15)))) && (Json.__default.MagOk(ip, fr));
    };
    static IsWs(c) {
      return ((((c).isEqualTo(new BigNumber(32))) || ((c).isEqualTo(new BigNumber(9)))) || ((c).isEqualTo(new BigNumber(10)))) || ((c).isEqualTo(new BigNumber(13)));
    };
    static Ws(t, i) {
      TAIL_CALL_START: while (true) {
        if ((((_dafny.ZERO).isLessThanOrEqualTo(i)) && ((i).isLessThan(new BigNumber((t).length)))) && (Json.__default.IsWs((t)[i]))) {
          let _in0 = t;
          let _in1 = (i).plus(_dafny.ONE);
          t = _in0;
          i = _in1;
          continue TAIL_CALL_START;
        } else {
          return i;
        }
      }
    };
    static ScanDigits(t, i) {
      TAIL_CALL_START: while (true) {
        if (((i).isLessThan(new BigNumber((t).length))) && (Json.__default.IsDig((t)[i]))) {
          let _in0 = t;
          let _in1 = (i).plus(_dafny.ONE);
          t = _in0;
          i = _in1;
          continue TAIL_CALL_START;
        } else {
          return i;
        }
      }
    };
    static IntEnd(t, k) {
      if (((k).isLessThan(new BigNumber((t).length))) && (((t)[k]).isEqualTo(new BigNumber(48)))) {
        return (k).plus(_dafny.ONE);
      } else if (((k).isLessThan(new BigNumber((t).length))) && (((new BigNumber(49)).isLessThanOrEqualTo((t)[k])) && (((t)[k]).isLessThanOrEqualTo(new BigNumber(57))))) {
        return Json.__default.ScanDigits(t, (k).plus(_dafny.ONE));
      } else {
        return new BigNumber(-1);
      }
    };
    static ExpMatches(t, L) {
      let _pat_let_tv0 = t;
      let _pat_let_tv1 = t;
      return ((((_dafny.ZERO).isLessThanOrEqualTo(L)) && ((L).isLessThan(new BigNumber((t).length)))) && ((((t)[L]).isEqualTo(new BigNumber(101))) || (((t)[L]).isEqualTo(new BigNumber(69))))) && (function (_pat_let0_0) {
        return function (_0_m) {
          return ((_0_m).isLessThan(new BigNumber((_pat_let_tv0).length))) && (Json.__default.IsDig((_pat_let_tv1)[_0_m]));
        }(_pat_let0_0);
      }((((((L).plus(_dafny.ONE)).isLessThan(new BigNumber((t).length))) && ((((t)[(L).plus(_dafny.ONE)]).isEqualTo(new BigNumber(43))) || (((t)[(L).plus(_dafny.ONE)]).isEqualTo(new BigNumber(45))))) ? ((L).plus(new BigNumber(2))) : ((L).plus(_dafny.ONE)))));
    };
    static ParseNum(t, j) {
      let _0_neg = ((t)[j]).isEqualTo(new BigNumber(45));
      let _1_k = ((_0_neg) ? ((j).plus(_dafny.ONE)) : (j));
      let _2_e = Json.__default.IntEnd(t, _1_k);
      if ((_2_e).isLessThan(_dafny.ZERO)) {
        return Json.R.create_Fail();
      } else {
        let _3_hasFrac = ((((_2_e).plus(_dafny.ONE)).isLessThan(new BigNumber((t).length))) && (((t)[_2_e]).isEqualTo(new BigNumber(46)))) && (Json.__default.IsDig((t)[(_2_e).plus(_dafny.ONE)]));
        let _4_L = ((_3_hasFrac) ? (Json.__default.ScanDigits(t, (_2_e).plus(_dafny.ONE))) : (_2_e));
        if (Json.__default.ExpMatches(t, _4_L)) {
          return Json.R.create_Fail();
        } else if (_3_hasFrac) {
          let _5_ip = Json.__default.ValSeq((t).slice(_1_k, _2_e));
          let _6_fr = Json.__default.FrOf(t, (_2_e).plus(_dafny.ONE), _4_L);
          if (Json.__default.ValidDec(_0_neg, _5_ip, _6_fr)) {
            return Json.R.create_Ok(Json.J.create_Dec(_0_neg, _5_ip, _6_fr), _4_L);
          } else {
            return Json.R.create_Fail();
          }
        } else {
          let _7_n = Json.__default.ValSeq((t).slice(_1_k, _2_e));
          if (((_0_neg) && ((_7_n).isEqualTo(_dafny.ZERO))) || ((Json.__default.MaxSafe).isLessThan(_7_n))) {
            return Json.R.create_Fail();
          } else {
            return Json.R.create_Ok(Json.J.create_Int(((_0_neg) ? ((_dafny.ZERO).minus(_7_n)) : (_7_n))), _4_L);
          }
        }
      }
    };
    static HexD(c) {
      if (((new BigNumber(48)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(57)))) {
        return (c).minus(new BigNumber(48));
      } else if (((new BigNumber(97)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(102)))) {
        return (c).minus(new BigNumber(87));
      } else if (((new BigNumber(65)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(70)))) {
        return (c).minus(new BigNumber(55));
      } else {
        return new BigNumber(-1);
      }
    };
    static Hex4(t, i) {
      if ((new BigNumber((t).length)).isLessThan((i).plus(new BigNumber(4)))) {
        return new BigNumber(-1);
      } else if (((((Json.__default.HexD((t)[i])).isLessThan(_dafny.ZERO)) || ((Json.__default.HexD((t)[(i).plus(_dafny.ONE)])).isLessThan(_dafny.ZERO))) || ((Json.__default.HexD((t)[(i).plus(new BigNumber(2))])).isLessThan(_dafny.ZERO))) || ((Json.__default.HexD((t)[(i).plus(new BigNumber(3))])).isLessThan(_dafny.ZERO))) {
        return new BigNumber(-1);
      } else {
        return ((((((Json.__default.HexD((t)[i])).multipliedBy(new BigNumber(16))).plus(Json.__default.HexD((t)[(i).plus(_dafny.ONE)]))).multipliedBy(new BigNumber(16))).plus(Json.__default.HexD((t)[(i).plus(new BigNumber(2))]))).multipliedBy(new BigNumber(16))).plus(Json.__default.HexD((t)[(i).plus(new BigNumber(3))]));
      }
    };
    static StrBody(t, i, acc) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((t).length)).isLessThanOrEqualTo(i)) {
          return Json.R.create_Fail();
        } else {
          let _0_c = (t)[i];
          if ((_0_c).isEqualTo(new BigNumber(34))) {
            return Json.R.create_Ok(acc, (i).plus(_dafny.ONE));
          } else if ((_0_c).isLessThan(new BigNumber(32))) {
            return Json.R.create_Fail();
          } else if ((_0_c).isEqualTo(new BigNumber(92))) {
            if ((new BigNumber((t).length)).isLessThanOrEqualTo((i).plus(_dafny.ONE))) {
              return Json.R.create_Fail();
            } else {
              let _1_e = (t)[(i).plus(_dafny.ONE)];
              if ((_1_e).isEqualTo(new BigNumber(34))) {
                let _in0 = t;
                let _in1 = (i).plus(new BigNumber(2));
                let _in2 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new BigNumber(34)));
                t = _in0;
                i = _in1;
                acc = _in2;
                continue TAIL_CALL_START;
              } else if ((_1_e).isEqualTo(new BigNumber(92))) {
                let _in3 = t;
                let _in4 = (i).plus(new BigNumber(2));
                let _in5 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new BigNumber(92)));
                t = _in3;
                i = _in4;
                acc = _in5;
                continue TAIL_CALL_START;
              } else if ((_1_e).isEqualTo(new BigNumber(47))) {
                let _in6 = t;
                let _in7 = (i).plus(new BigNumber(2));
                let _in8 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new BigNumber(47)));
                t = _in6;
                i = _in7;
                acc = _in8;
                continue TAIL_CALL_START;
              } else if ((_1_e).isEqualTo(new BigNumber(98))) {
                let _in9 = t;
                let _in10 = (i).plus(new BigNumber(2));
                let _in11 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new BigNumber(8)));
                t = _in9;
                i = _in10;
                acc = _in11;
                continue TAIL_CALL_START;
              } else if ((_1_e).isEqualTo(new BigNumber(102))) {
                let _in12 = t;
                let _in13 = (i).plus(new BigNumber(2));
                let _in14 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new BigNumber(12)));
                t = _in12;
                i = _in13;
                acc = _in14;
                continue TAIL_CALL_START;
              } else if ((_1_e).isEqualTo(new BigNumber(110))) {
                let _in15 = t;
                let _in16 = (i).plus(new BigNumber(2));
                let _in17 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new BigNumber(10)));
                t = _in15;
                i = _in16;
                acc = _in17;
                continue TAIL_CALL_START;
              } else if ((_1_e).isEqualTo(new BigNumber(114))) {
                let _in18 = t;
                let _in19 = (i).plus(new BigNumber(2));
                let _in20 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new BigNumber(13)));
                t = _in18;
                i = _in19;
                acc = _in20;
                continue TAIL_CALL_START;
              } else if ((_1_e).isEqualTo(new BigNumber(116))) {
                let _in21 = t;
                let _in22 = (i).plus(new BigNumber(2));
                let _in23 = _dafny.Seq.Concat(acc, _dafny.Seq.of(new BigNumber(9)));
                t = _in21;
                i = _in22;
                acc = _in23;
                continue TAIL_CALL_START;
              } else if ((_1_e).isEqualTo(new BigNumber(117))) {
                let _2_h = Json.__default.Hex4(t, (i).plus(new BigNumber(2)));
                if ((_2_h).isLessThan(_dafny.ZERO)) {
                  return Json.R.create_Fail();
                } else {
                  let _in24 = t;
                  let _in25 = (i).plus(new BigNumber(6));
                  let _in26 = _dafny.Seq.Concat(acc, _dafny.Seq.of(_2_h));
                  t = _in24;
                  i = _in25;
                  acc = _in26;
                  continue TAIL_CALL_START;
                }
              } else {
                return Json.R.create_Fail();
              }
            }
          } else {
            let _in27 = t;
            let _in28 = (i).plus(_dafny.ONE);
            let _in29 = _dafny.Seq.Concat(acc, _dafny.Seq.of(_0_c));
            t = _in27;
            i = _in28;
            acc = _in29;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static PlainEnd(t, i) {
      TAIL_CALL_START: while (true) {
        if (((((i).isLessThan(new BigNumber((t).length))) && (!((t)[i]).isEqualTo(new BigNumber(34)))) && (!((t)[i]).isEqualTo(new BigNumber(92)))) && ((new BigNumber(32)).isLessThanOrEqualTo((t)[i]))) {
          let _in0 = t;
          let _in1 = (i).plus(_dafny.ONE);
          t = _in0;
          i = _in1;
          continue TAIL_CALL_START;
        } else {
          return i;
        }
      }
    };
    static StrBodyF(t, i, acc) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((t).length)).isLessThanOrEqualTo(i)) {
          return Json.R.create_Fail();
        } else {
          let _0_j = Json.__default.PlainEnd(t, i);
          let _1_acc2 = (((_0_j).isEqualTo(i)) ? (acc) : (_dafny.Seq.Concat(acc, (t).slice(i, _0_j))));
          if ((new BigNumber((t).length)).isLessThanOrEqualTo(_0_j)) {
            return Json.R.create_Fail();
          } else {
            let _2_c = (t)[_0_j];
            if ((_2_c).isEqualTo(new BigNumber(34))) {
              return Json.R.create_Ok(_1_acc2, (_0_j).plus(_dafny.ONE));
            } else if ((_2_c).isLessThan(new BigNumber(32))) {
              return Json.R.create_Fail();
            } else if ((_2_c).isEqualTo(new BigNumber(92))) {
              if ((new BigNumber((t).length)).isLessThanOrEqualTo((_0_j).plus(_dafny.ONE))) {
                return Json.R.create_Fail();
              } else {
                let _3_e = (t)[(_0_j).plus(_dafny.ONE)];
                if ((_3_e).isEqualTo(new BigNumber(34))) {
                  let _in0 = t;
                  let _in1 = (_0_j).plus(new BigNumber(2));
                  let _in2 = _dafny.Seq.Concat(_1_acc2, _dafny.Seq.of(new BigNumber(34)));
                  t = _in0;
                  i = _in1;
                  acc = _in2;
                  continue TAIL_CALL_START;
                } else if ((_3_e).isEqualTo(new BigNumber(92))) {
                  let _in3 = t;
                  let _in4 = (_0_j).plus(new BigNumber(2));
                  let _in5 = _dafny.Seq.Concat(_1_acc2, _dafny.Seq.of(new BigNumber(92)));
                  t = _in3;
                  i = _in4;
                  acc = _in5;
                  continue TAIL_CALL_START;
                } else if ((_3_e).isEqualTo(new BigNumber(47))) {
                  let _in6 = t;
                  let _in7 = (_0_j).plus(new BigNumber(2));
                  let _in8 = _dafny.Seq.Concat(_1_acc2, _dafny.Seq.of(new BigNumber(47)));
                  t = _in6;
                  i = _in7;
                  acc = _in8;
                  continue TAIL_CALL_START;
                } else if ((_3_e).isEqualTo(new BigNumber(98))) {
                  let _in9 = t;
                  let _in10 = (_0_j).plus(new BigNumber(2));
                  let _in11 = _dafny.Seq.Concat(_1_acc2, _dafny.Seq.of(new BigNumber(8)));
                  t = _in9;
                  i = _in10;
                  acc = _in11;
                  continue TAIL_CALL_START;
                } else if ((_3_e).isEqualTo(new BigNumber(102))) {
                  let _in12 = t;
                  let _in13 = (_0_j).plus(new BigNumber(2));
                  let _in14 = _dafny.Seq.Concat(_1_acc2, _dafny.Seq.of(new BigNumber(12)));
                  t = _in12;
                  i = _in13;
                  acc = _in14;
                  continue TAIL_CALL_START;
                } else if ((_3_e).isEqualTo(new BigNumber(110))) {
                  let _in15 = t;
                  let _in16 = (_0_j).plus(new BigNumber(2));
                  let _in17 = _dafny.Seq.Concat(_1_acc2, _dafny.Seq.of(new BigNumber(10)));
                  t = _in15;
                  i = _in16;
                  acc = _in17;
                  continue TAIL_CALL_START;
                } else if ((_3_e).isEqualTo(new BigNumber(114))) {
                  let _in18 = t;
                  let _in19 = (_0_j).plus(new BigNumber(2));
                  let _in20 = _dafny.Seq.Concat(_1_acc2, _dafny.Seq.of(new BigNumber(13)));
                  t = _in18;
                  i = _in19;
                  acc = _in20;
                  continue TAIL_CALL_START;
                } else if ((_3_e).isEqualTo(new BigNumber(116))) {
                  let _in21 = t;
                  let _in22 = (_0_j).plus(new BigNumber(2));
                  let _in23 = _dafny.Seq.Concat(_1_acc2, _dafny.Seq.of(new BigNumber(9)));
                  t = _in21;
                  i = _in22;
                  acc = _in23;
                  continue TAIL_CALL_START;
                } else if ((_3_e).isEqualTo(new BigNumber(117))) {
                  let _4_h = Json.__default.Hex4(t, (_0_j).plus(new BigNumber(2)));
                  if ((_4_h).isLessThan(_dafny.ZERO)) {
                    return Json.R.create_Fail();
                  } else {
                    let _in24 = t;
                    let _in25 = (_0_j).plus(new BigNumber(6));
                    let _in26 = _dafny.Seq.Concat(_1_acc2, _dafny.Seq.of(_4_h));
                    t = _in24;
                    i = _in25;
                    acc = _in26;
                    continue TAIL_CALL_START;
                  }
                } else {
                  return Json.R.create_Fail();
                }
              }
            } else {
              return Json.R.create_Fail();
            }
          }
        }
      }
    };
    static ParseStr(t, i) {
      let _source0 = Json.__default.StrBodyF(t, (i).plus(_dafny.ONE), _dafny.Seq.of());
      {
        if (_source0.is_Fail) {
          return Json.R.create_Fail();
        }
      }
      {
        let _0_s = (_source0).v;
        let _1_p = (_source0).pos;
        if (Utf.__default.Valid16(_0_s)) {
          return Json.R.create_Ok(_0_s, _1_p);
        } else {
          return Json.R.create_Fail();
        }
      }
    };
    static StartsWith(t, j, lit) {
      return (((_dafny.ZERO).isLessThanOrEqualTo(j)) && (((j).plus(new BigNumber((lit).length))).isLessThanOrEqualTo(new BigNumber((t).length)))) && (_dafny.areEqual((t).slice(j, (j).plus(new BigNumber((lit).length))), lit));
    };
    static HasKey(acc, k) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((acc).length)), false, function (_exists_var_0) {
        let _0_i = _exists_var_0;
        return (((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((acc).length)))) && (_dafny.areEqual(((acc)[_0_i]).dtor_k, k));
      });
    };
    static ParseValue(t, i, d) {
      let _0_j = Json.__default.Ws(t, i);
      if ((new BigNumber((t).length)).isLessThanOrEqualTo(_0_j)) {
        return Json.R.create_Fail();
      } else {
        let _1_c = (t)[_0_j];
        if ((_1_c).isEqualTo(new BigNumber(123))) {
          if ((Json.__default.MaxDepth).isLessThan(d)) {
            return Json.R.create_Fail();
          } else {
            return Json.__default.ObjStart(t, (_0_j).plus(_dafny.ONE), d);
          }
        } else if ((_1_c).isEqualTo(new BigNumber(91))) {
          if ((Json.__default.MaxDepth).isLessThan(d)) {
            return Json.R.create_Fail();
          } else {
            return Json.__default.ArrStart(t, (_0_j).plus(_dafny.ONE), d);
          }
        } else if ((_1_c).isEqualTo(new BigNumber(34))) {
          let _source0 = Json.__default.ParseStr(t, _0_j);
          {
            if (_source0.is_Fail) {
              return Json.R.create_Fail();
            }
          }
          {
            let _2_s = (_source0).v;
            let _3_p = (_source0).pos;
            return Json.R.create_Ok(Json.J.create_Str(_2_s), _3_p);
          }
        } else if (((_1_c).isEqualTo(new BigNumber(45))) || (Json.__default.IsDig(_1_c))) {
          return Json.__default.ParseNum(t, _0_j);
        } else if (Json.__default.StartsWith(t, _0_j, Json.__default.LitTrue)) {
          return Json.R.create_Ok(Json.J.create_Bool(true), (_0_j).plus(new BigNumber(4)));
        } else if (Json.__default.StartsWith(t, _0_j, Json.__default.LitFalse)) {
          return Json.R.create_Ok(Json.J.create_Bool(false), (_0_j).plus(new BigNumber(5)));
        } else if (Json.__default.StartsWith(t, _0_j, Json.__default.LitNull)) {
          return Json.R.create_Ok(Json.J.create_Null(), (_0_j).plus(new BigNumber(4)));
        } else {
          return Json.R.create_Fail();
        }
      }
    };
    static ArrStart(t, i, d) {
      let _0_j = Json.__default.Ws(t, i);
      if (((_0_j).isLessThan(new BigNumber((t).length))) && (((t)[_0_j]).isEqualTo(new BigNumber(93)))) {
        return Json.R.create_Ok(Json.J.create_Arr(_dafny.Seq.of()), (_0_j).plus(_dafny.ONE));
      } else {
        return Json.__default.ArrLoop(t, i, d, _dafny.Seq.of());
      }
    };
    static ArrLoop(t, i, d, acc) {
      let _source0 = Json.__default.ParseValue(t, i, (d).plus(_dafny.ONE));
      {
        if (_source0.is_Fail) {
          return Json.R.create_Fail();
        }
      }
      {
        let _0_v = (_source0).v;
        let _1_p = (_source0).pos;
        let _2_j = Json.__default.Ws(t, _1_p);
        if ((new BigNumber((t).length)).isLessThanOrEqualTo(_2_j)) {
          return Json.R.create_Fail();
        } else if (((t)[_2_j]).isEqualTo(new BigNumber(44))) {
          return Json.__default.ArrLoop(t, (_2_j).plus(_dafny.ONE), d, _dafny.Seq.Concat(acc, _dafny.Seq.of(_0_v)));
        } else if (((t)[_2_j]).isEqualTo(new BigNumber(93))) {
          return Json.R.create_Ok(Json.J.create_Arr(_dafny.Seq.Concat(acc, _dafny.Seq.of(_0_v))), (_2_j).plus(_dafny.ONE));
        } else {
          return Json.R.create_Fail();
        }
      }
    };
    static ObjStart(t, i, d) {
      let _0_j = Json.__default.Ws(t, i);
      if (((_0_j).isLessThan(new BigNumber((t).length))) && (((t)[_0_j]).isEqualTo(new BigNumber(125)))) {
        return Json.R.create_Ok(Json.J.create_Obj(_dafny.Seq.of()), (_0_j).plus(_dafny.ONE));
      } else {
        return Json.__default.ObjLoop(t, i, d, _dafny.Seq.of());
      }
    };
    static ObjLoop(t, i, d, acc) {
      let _0_j = Json.__default.Ws(t, i);
      if (((new BigNumber((t).length)).isLessThanOrEqualTo(_0_j)) || (!((t)[_0_j]).isEqualTo(new BigNumber(34)))) {
        return Json.R.create_Fail();
      } else {
        let _source0 = Json.__default.ParseStr(t, _0_j);
        {
          if (_source0.is_Fail) {
            return Json.R.create_Fail();
          }
        }
        {
          let _1_k = (_source0).v;
          let _2_p = (_source0).pos;
          if (Json.__default.HasKey(acc, _1_k)) {
            return Json.R.create_Fail();
          } else {
            let _3_j2 = Json.__default.Ws(t, _2_p);
            if (((new BigNumber((t).length)).isLessThanOrEqualTo(_3_j2)) || (!((t)[_3_j2]).isEqualTo(new BigNumber(58)))) {
              return Json.R.create_Fail();
            } else {
              let _source1 = Json.__default.ParseValue(t, (_3_j2).plus(_dafny.ONE), (d).plus(_dafny.ONE));
              {
                if (_source1.is_Fail) {
                  return Json.R.create_Fail();
                }
              }
              {
                let _4_v = (_source1).v;
                let _5_q = (_source1).pos;
                let _6_j3 = Json.__default.Ws(t, _5_q);
                if ((new BigNumber((t).length)).isLessThanOrEqualTo(_6_j3)) {
                  return Json.R.create_Fail();
                } else if (((t)[_6_j3]).isEqualTo(new BigNumber(44))) {
                  return Json.__default.ObjLoop(t, (_6_j3).plus(_dafny.ONE), d, _dafny.Seq.Concat(acc, _dafny.Seq.of(Json.KV.create_KV(_1_k, _4_v))));
                } else if (((t)[_6_j3]).isEqualTo(new BigNumber(125))) {
                  return Json.R.create_Ok(Json.J.create_Obj(_dafny.Seq.Concat(acc, _dafny.Seq.of(Json.KV.create_KV(_1_k, _4_v)))), (_6_j3).plus(_dafny.ONE));
                } else {
                  return Json.R.create_Fail();
                }
              }
            }
          }
        }
      }
    };
    static ParseTop(t) {
      if ((Json.__default.MaxBytes).isLessThan(Utf.__default.Utf8LenLoose(t))) {
        return Json.Option.create_None();
      } else {
        let _source0 = Json.__default.ParseValue(t, _dafny.ZERO, _dafny.ONE);
        {
          if (_source0.is_Fail) {
            return Json.Option.create_None();
          }
        }
        {
          let _0_v = (_source0).v;
          let _1_p = (_source0).pos;
          if ((Json.__default.Ws(t, _1_p)).isEqualTo(new BigNumber((t).length))) {
            return Json.Option.create_Some(_0_v);
          } else {
            return Json.Option.create_None();
          }
        }
      }
    };
    static DistinctKeys(kv) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((kv).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((kv).length)))) || (_dafny.Quantifier(_dafny.IntegerRange((_0_i).plus(_dafny.ONE), new BigNumber((kv).length)), true, function (_forall_var_1) {
          let _1_j = _forall_var_1;
          return !(((_0_i).isLessThan(_1_j)) && ((_1_j).isLessThan(new BigNumber((kv).length)))) || (!_dafny.areEqual(((kv)[_0_i]).dtor_k, ((kv)[_1_j]).dtor_k));
        }));
      });
    };
    static Valid(v, d) {
      let _source0 = v;
      {
        if (_source0.is_Null) {
          return true;
        }
      }
      {
        if (_source0.is_Bool) {
          return true;
        }
      }
      {
        if (_source0.is_Int) {
          let _0_n = (_source0).n;
          return (((_dafny.ZERO).minus(Json.__default.MaxSafe)).isLessThanOrEqualTo(_0_n)) && ((_0_n).isLessThanOrEqualTo(Json.__default.MaxSafe));
        }
      }
      {
        if (_source0.is_Dec) {
          let _1_neg = (_source0).neg;
          let _2_ip = (_source0).ip;
          let _3_fr = (_source0).fr;
          return Json.__default.ValidDec(_1_neg, _2_ip, _3_fr);
        }
      }
      {
        if (_source0.is_Str) {
          let _4_s = (_source0).s;
          return Utf.__default.Valid16(_4_s);
        }
      }
      {
        if (_source0.is_Arr) {
          let _5_a = (_source0).a;
          return ((d).isLessThanOrEqualTo(Json.__default.MaxDepth)) && (Json.__default.ValidElems(_5_a, (d).plus(_dafny.ONE)));
        }
      }
      {
        let _6_kv = (_source0).kv;
        return (((d).isLessThanOrEqualTo(Json.__default.MaxDepth)) && (Json.__default.ValidMembers(_6_kv, (d).plus(_dafny.ONE)))) && (Json.__default.DistinctKeys(_6_kv));
      }
    };
    static ValidElems(a, d) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((a).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((a).length)))) || (Json.__default.Valid((a)[_0_i], d));
      });
    };
    static ValidMembers(kv, d) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((kv).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((kv).length)))) || ((Utf.__default.Valid16(((kv)[_0_i]).dtor_k)) && (Json.__default.Valid(((kv)[_0_i]).dtor_v, d)));
      });
    };
    static Insert(x, s) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((s).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(x));
        } else if (Utf.__default.KLess((x).dtor_k, ((s)[_dafny.ZERO]).dtor_k)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.Concat(_dafny.Seq.of(x), s));
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of((s)[_dafny.ZERO]));
          let _in0 = x;
          let _in1 = (s).slice(_dafny.ONE);
          x = _in0;
          s = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static SortKV(kv) {
      if ((new BigNumber((kv).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Seq.of();
      } else {
        return Json.__default.Insert((kv)[_dafny.ZERO], Json.__default.SortKV((kv).slice(_dafny.ONE)));
      }
    };
    static StrictSorted(s) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((s).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((s).length)))) || (_dafny.Quantifier(_dafny.IntegerRange((_0_i).plus(_dafny.ONE), new BigNumber((s).length)), true, function (_forall_var_1) {
          let _1_j = _forall_var_1;
          return !(((_0_i).isLessThan(_1_j)) && ((_1_j).isLessThan(new BigNumber((s).length)))) || (Utf.__default.KLess(((s)[_0_i]).dtor_k, ((s)[_1_j]).dtor_k));
        }));
      });
    };
    static KeysValid(s) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((s).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((s).length)))) || (Utf.__default.Valid16(((s)[_0_i]).dtor_k));
      });
    };
    static NormJ(v) {
      let _source0 = v;
      {
        if (_source0.is_Arr) {
          let _0_a = (_source0).a;
          return Json.J.create_Arr(Json.__default.NormElems(_0_a));
        }
      }
      {
        if (_source0.is_Obj) {
          let _1_kv = (_source0).kv;
          return Json.J.create_Obj(Json.__default.SortKV(Json.__default.NormMembers(_1_kv)));
        }
      }
      {
        return v;
      }
    };
    static NormElems(a) {
      if ((new BigNumber((a).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Seq.of();
      } else {
        return _dafny.Seq.Concat(_dafny.Seq.of(Json.__default.NormJ((a)[_dafny.ZERO])), Json.__default.NormElems((a).slice(_dafny.ONE)));
      }
    };
    static NormMembers(kv) {
      if ((new BigNumber((kv).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Seq.of();
      } else {
        return _dafny.Seq.Concat(_dafny.Seq.of(Json.KV.create_KV(((kv)[_dafny.ZERO]).dtor_k, Json.__default.NormJ(((kv)[_dafny.ZERO]).dtor_v))), Json.__default.NormMembers((kv).slice(_dafny.ONE)));
      }
    };
    static Canon(v) {
      let _source0 = v;
      {
        if (_source0.is_Arr) {
          let _0_a = (_source0).a;
          return Json.__default.CanonElems(_0_a);
        }
      }
      {
        if (_source0.is_Obj) {
          let _1_kv = (_source0).kv;
          return (Json.__default.StrictSorted(_1_kv)) && (Json.__default.CanonMembers(_1_kv));
        }
      }
      {
        return true;
      }
    };
    static CanonElems(a) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((a).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((a).length)))) || (Json.__default.Canon((a)[_0_i]));
      });
    };
    static CanonMembers(kv) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((kv).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((kv).length)))) || (Json.__default.Canon(((kv)[_0_i]).dtor_v));
      });
    };
    static HexL(v) {
      if ((v).isLessThan(new BigNumber(10))) {
        return (new BigNumber(48)).plus(v);
      } else {
        return (new BigNumber(97)).plus((v).minus(new BigNumber(10)));
      }
    };
    static PrintU(x) {
      if ((x).isEqualTo(new BigNumber(34))) {
        return _dafny.Seq.of(new BigNumber(92), new BigNumber(34));
      } else if ((x).isEqualTo(new BigNumber(92))) {
        return _dafny.Seq.of(new BigNumber(92), new BigNumber(92));
      } else if ((x).isEqualTo(new BigNumber(8))) {
        return _dafny.Seq.of(new BigNumber(92), new BigNumber(98));
      } else if ((x).isEqualTo(new BigNumber(12))) {
        return _dafny.Seq.of(new BigNumber(92), new BigNumber(102));
      } else if ((x).isEqualTo(new BigNumber(10))) {
        return _dafny.Seq.of(new BigNumber(92), new BigNumber(110));
      } else if ((x).isEqualTo(new BigNumber(13))) {
        return _dafny.Seq.of(new BigNumber(92), new BigNumber(114));
      } else if ((x).isEqualTo(new BigNumber(9))) {
        return _dafny.Seq.of(new BigNumber(92), new BigNumber(116));
      } else if (((_dafny.ZERO).isLessThanOrEqualTo(x)) && ((x).isLessThan(new BigNumber(32)))) {
        return _dafny.Seq.of(new BigNumber(92), new BigNumber(117), new BigNumber(48), new BigNumber(48), Json.__default.HexL(_dafny.EuclideanDivision(x, new BigNumber(16))), Json.__default.HexL((x).mod(new BigNumber(16))));
      } else {
        return _dafny.Seq.of(x);
      }
    };
    static PrintBody(s) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((s).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, Json.__default.PrintU((s)[_dafny.ZERO]));
          let _in0 = (s).slice(_dafny.ONE);
          s = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static PrintNat(n) {
      if ((n).isLessThan(_dafny.ZERO)) {
        return Json.__default.Dig(_dafny.ZERO);
      } else {
        return Json.__default.Dig(n);
      }
    };
    static Print(v) {
      let _source0 = v;
      {
        if (_source0.is_Null) {
          return Json.__default.LitNull;
        }
      }
      {
        if (_source0.is_Bool) {
          let _0_b = (_source0).b;
          if (_0_b) {
            return Json.__default.LitTrue;
          } else {
            return Json.__default.LitFalse;
          }
        }
      }
      {
        if (_source0.is_Int) {
          let _1_n = (_source0).n;
          if ((_1_n).isLessThan(_dafny.ZERO)) {
            return _dafny.Seq.Concat(_dafny.Seq.of(new BigNumber(45)), Json.__default.PrintNat((_dafny.ZERO).minus(_1_n)));
          } else {
            return Json.__default.PrintNat(_1_n);
          }
        }
      }
      {
        if (_source0.is_Dec) {
          let _2_neg = (_source0).neg;
          let _3_ip = (_source0).ip;
          let _4_fr = (_source0).fr;
          return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(((_2_neg) ? (_dafny.Seq.of(new BigNumber(45))) : (_dafny.Seq.of())), Json.__default.PrintNat(_3_ip)), _dafny.Seq.of(new BigNumber(46))), Json.__default.FrTxt(_4_fr));
        }
      }
      {
        if (_source0.is_Str) {
          let _5_s = (_source0).s;
          return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(new BigNumber(34)), Json.__default.PrintBody(_5_s)), _dafny.Seq.of(new BigNumber(34)));
        }
      }
      {
        if (_source0.is_Arr) {
          let _6_a = (_source0).a;
          return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(new BigNumber(91)), Json.__default.PrintElems(_6_a)), _dafny.Seq.of(new BigNumber(93)));
        }
      }
      {
        let _7_kv = (_source0).kv;
        return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(new BigNumber(123)), Json.__default.PrintMembers(_7_kv)), _dafny.Seq.of(new BigNumber(125)));
      }
    };
    static PrintElems(a) {
      if ((new BigNumber((a).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Seq.of();
      } else if ((new BigNumber((a).length)).isEqualTo(_dafny.ONE)) {
        return Json.__default.Print((a)[_dafny.ZERO]);
      } else {
        return _dafny.Seq.Concat(_dafny.Seq.Concat(Json.__default.Print((a)[_dafny.ZERO]), _dafny.Seq.of(new BigNumber(44))), Json.__default.PrintElems((a).slice(_dafny.ONE)));
      }
    };
    static PrintMembers(kv) {
      if ((new BigNumber((kv).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Seq.of();
      } else {
        return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(new BigNumber(34)), Json.__default.PrintBody(((kv)[_dafny.ZERO]).dtor_k)), _dafny.Seq.of(new BigNumber(34), new BigNumber(58))), Json.__default.Print(((kv)[_dafny.ZERO]).dtor_v)), (((new BigNumber((kv).length)).isEqualTo(_dafny.ONE)) ? (_dafny.Seq.of()) : (_dafny.Seq.Concat(_dafny.Seq.of(new BigNumber(44)), Json.__default.PrintMembers((kv).slice(_dafny.ONE))))));
      }
    };
    static CanonText(v) {
      if (Json.__default.Valid(v, _dafny.ONE)) {
        return Json.Option.create_Some(Json.__default.Print(Json.__default.NormJ(v)));
      } else {
        return Json.Option.create_None();
      }
    };
    static Delim(rest) {
      return ((new BigNumber((rest).length)).isEqualTo(_dafny.ZERO)) || ((_dafny.Set.fromElements(new BigNumber(32), new BigNumber(9), new BigNumber(10), new BigNumber(13), new BigNumber(44), new BigNumber(93), new BigNumber(125))).contains((rest)[_dafny.ZERO]));
    };
    static get MaxSafe() {
      return new BigNumber(9007199254740991);
    };
    static get MaxDepth() {
      return new BigNumber(32);
    };
    static get LitTrue() {
      return _dafny.Seq.of(new BigNumber(116), new BigNumber(114), new BigNumber(117), new BigNumber(101));
    };
    static get LitFalse() {
      return _dafny.Seq.of(new BigNumber(102), new BigNumber(97), new BigNumber(108), new BigNumber(115), new BigNumber(101));
    };
    static get LitNull() {
      return _dafny.Seq.of(new BigNumber(110), new BigNumber(117), new BigNumber(108), new BigNumber(108));
    };
    static get MaxBytes() {
      return new BigNumber(1048576);
    };
  };

  $module.KV = class KV {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_KV(k, v) {
      let $dt = new KV(0);
      $dt.k = k;
      $dt.v = v;
      return $dt;
    }
    get is_KV() { return this.$tag === 0; }
    get dtor_k() { return this.k; }
    get dtor_v() { return this.v; }
    toString() {
      if (this.$tag === 0) {
        return "Json.KV.KV" + "(" + _dafny.toString(this.k) + ", " + _dafny.toString(this.v) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.k, other.k) && _dafny.areEqual(this.v, other.v);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Json.KV.create_KV(_dafny.Seq.of(), Json.J.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return KV.Default();
        }
      };
    }
  }

  $module.J = class J {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Null() {
      let $dt = new J(0);
      return $dt;
    }
    static create_Bool(b) {
      let $dt = new J(1);
      $dt.b = b;
      return $dt;
    }
    static create_Int(n) {
      let $dt = new J(2);
      $dt.n = n;
      return $dt;
    }
    static create_Dec(neg, ip, fr) {
      let $dt = new J(3);
      $dt.neg = neg;
      $dt.ip = ip;
      $dt.fr = fr;
      return $dt;
    }
    static create_Str(s) {
      let $dt = new J(4);
      $dt.s = s;
      return $dt;
    }
    static create_Arr(a) {
      let $dt = new J(5);
      $dt.a = a;
      return $dt;
    }
    static create_Obj(kv) {
      let $dt = new J(6);
      $dt.kv = kv;
      return $dt;
    }
    get is_Null() { return this.$tag === 0; }
    get is_Bool() { return this.$tag === 1; }
    get is_Int() { return this.$tag === 2; }
    get is_Dec() { return this.$tag === 3; }
    get is_Str() { return this.$tag === 4; }
    get is_Arr() { return this.$tag === 5; }
    get is_Obj() { return this.$tag === 6; }
    get dtor_b() { return this.b; }
    get dtor_n() { return this.n; }
    get dtor_neg() { return this.neg; }
    get dtor_ip() { return this.ip; }
    get dtor_fr() { return this.fr; }
    get dtor_s() { return this.s; }
    get dtor_a() { return this.a; }
    get dtor_kv() { return this.kv; }
    toString() {
      if (this.$tag === 0) {
        return "Json.J.Null";
      } else if (this.$tag === 1) {
        return "Json.J.Bool" + "(" + _dafny.toString(this.b) + ")";
      } else if (this.$tag === 2) {
        return "Json.J.Int" + "(" + _dafny.toString(this.n) + ")";
      } else if (this.$tag === 3) {
        return "Json.J.Dec" + "(" + _dafny.toString(this.neg) + ", " + _dafny.toString(this.ip) + ", " + _dafny.toString(this.fr) + ")";
      } else if (this.$tag === 4) {
        return "Json.J.Str" + "(" + _dafny.toString(this.s) + ")";
      } else if (this.$tag === 5) {
        return "Json.J.Arr" + "(" + _dafny.toString(this.a) + ")";
      } else if (this.$tag === 6) {
        return "Json.J.Obj" + "(" + _dafny.toString(this.kv) + ")";
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
        return other.$tag === 1 && this.b === other.b;
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.n, other.n);
      } else if (this.$tag === 3) {
        return other.$tag === 3 && this.neg === other.neg && _dafny.areEqual(this.ip, other.ip) && _dafny.areEqual(this.fr, other.fr);
      } else if (this.$tag === 4) {
        return other.$tag === 4 && _dafny.areEqual(this.s, other.s);
      } else if (this.$tag === 5) {
        return other.$tag === 5 && _dafny.areEqual(this.a, other.a);
      } else if (this.$tag === 6) {
        return other.$tag === 6 && _dafny.areEqual(this.kv, other.kv);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Json.J.create_Null();
    }
    static Rtd() {
      return class {
        static get Default() {
          return J.Default();
        }
      };
    }
  }

  $module.R = class R {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Fail() {
      let $dt = new R(0);
      return $dt;
    }
    static create_Ok(v, pos) {
      let $dt = new R(1);
      $dt.v = v;
      $dt.pos = pos;
      return $dt;
    }
    get is_Fail() { return this.$tag === 0; }
    get is_Ok() { return this.$tag === 1; }
    get dtor_v() { return this.v; }
    get dtor_pos() { return this.pos; }
    toString() {
      if (this.$tag === 0) {
        return "Json.R.Fail";
      } else if (this.$tag === 1) {
        return "Json.R.Ok" + "(" + _dafny.toString(this.v) + ", " + _dafny.toString(this.pos) + ")";
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
        return other.$tag === 1 && _dafny.areEqual(this.v, other.v) && _dafny.areEqual(this.pos, other.pos);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Json.R.create_Fail();
    }
    static Rtd() {
      return class {
        static get Default() {
          return R.Default();
        }
      };
    }
  }

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
        return "Json.Option.None";
      } else if (this.$tag === 1) {
        return "Json.Option.Some" + "(" + _dafny.toString(this.v) + ")";
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
      return Json.Option.create_None();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Option.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module Json
let Api = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Api._default";
    }
    _parentTraits() {
      return [];
    }
    static CanonicalOfText(t) {
      let _source0 = Json.__default.ParseTop(t);
      {
        if (_source0.is_None) {
          return Json.Option.create_None();
        }
      }
      {
        let _0_v = (_source0).v;
        return Json.__default.CanonText(_0_v);
      }
    };
    static CanonicalOfValue(v) {
      return Json.__default.CanonText(v);
    };
    static CompareUtf8(a, b) {
      if (_dafny.areEqual(a, b)) {
        return _dafny.ZERO;
      } else if (Utf.__default.KLess(a, b)) {
        return new BigNumber(-1);
      } else {
        return _dafny.ONE;
      }
    };
    static B64Decode(s, len) {
      return B64.__default.DecodeStrict(s, len);
    };
    static B64Encode(b) {
      return B64.__default.Enc(b);
    };
    static HexDecode(s) {
      return B64.__default.HexDec(s);
    };
    static HexEncode(b) {
      return B64.__default.HexEnc(b);
    };
  };
  return $module;
})(); // end of module Api
let _module = (function() {
  let $module = {};

  return $module;
})(); // end of module _module

// ---- exports (appended by formal/dafny/build-ext.sh) ----
module.exports = { _dafny, Utf, B64, Json, Api };
