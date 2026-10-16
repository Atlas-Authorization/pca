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
let Fast = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Fast._default";
    }
    _parentTraits() {
      return [];
    }
    static SkipWs(t, i) {
      let j = 0;
      j = i;
      let _0_n;
      _0_n = (t).length;
      while (((j) < (_0_n)) && ((((((t)[j]) === (32)) || (((t)[j]) === (9))) || (((t)[j]) === (10))) || (((t)[j]) === (13)))) {
        j = (j) + (1);
      }
      return j;
    }
    static Utf8LenN(t) {
      let r = 0;
      let _0_i;
      _0_i = 0;
      let _1_n;
      _1_n = (t).length;
      r = 0;
      while ((_0_i) < (_1_n)) {
        let _2_c;
        _2_c = (t)[_0_i];
        if (((((55296) <= (_2_c)) && ((_2_c) <= (56319))) && (((_0_i) + (1)) < (_1_n))) && (((56320) <= ((t)[(_0_i) + (1)])) && (((t)[(_0_i) + (1)]) <= (57343)))) {
          r = (r) + (4);
          _0_i = (_0_i) + (2);
        } else {
          r = (r) + ((((_2_c) < (128)) ? (1) : ((((_2_c) < (2048)) ? (2) : (3)))));
          _0_i = (_0_i) + (1);
        }
      }
      return r;
    }
    static ScanDigitsN(t, i) {
      let j = 0;
      j = i;
      let _0_n;
      _0_n = (t).length;
      while (((j) < (_0_n)) && (((48) <= ((t)[j])) && (((t)[j]) <= (57)))) {
        j = (j) + (1);
      }
      return j;
    }
    static NumM(t, j) {
      let ok = false;
      let p = 0;
      let _0_n;
      _0_n = (t).length;
      let _1_neg;
      _1_neg = ((t)[j]) === (45);
      let _2_k;
      if (_1_neg) {
        _2_k = (j) + (1);
      } else {
        _2_k = j;
      }
      let _3_e = 0;
      if (((_2_k) < (_0_n)) && (((t)[_2_k]) === (48))) {
        _3_e = (_2_k) + (1);
      } else if (((_2_k) < (_0_n)) && (((49) <= ((t)[_2_k])) && (((t)[_2_k]) <= (57)))) {
        let _out0;
        _out0 = Fast.__default.ScanDigitsN(t, (_2_k) + (1));
        _3_e = _out0;
      } else {
        let _rhs0 = false;
        let _rhs1 = 0;
        ok = _rhs0;
        p = _rhs1;
        return [ok, p];
      }
      let _4_hasFrac;
      _4_hasFrac = ((((_3_e) + (1)) < (_0_n)) && (((t)[_3_e]) === (46))) && (((48) <= ((t)[(_3_e) + (1)])) && (((t)[(_3_e) + (1)]) <= (57)));
      let _5_L;
      _5_L = _3_e;
      if (_4_hasFrac) {
        let _out1;
        _out1 = Fast.__default.ScanDigitsN(t, (_3_e) + (1));
        _5_L = _out1;
      }
      let _pat_let_tv0 = _0_n;
      let _pat_let_tv1 = t;
      let _pat_let_tv2 = t;
      let _6_expm;
      _6_expm = (((_5_L) < (_0_n)) && ((((t)[_5_L]) === (101)) || (((t)[_5_L]) === (69)))) && (function (_pat_let1_0) {
        return function (_7_m) {
          return ((_7_m) < (_pat_let_tv0)) && (((48) <= ((_pat_let_tv1)[_7_m])) && (((_pat_let_tv2)[_7_m]) <= (57)));
        }(_pat_let1_0);
      }((((((_5_L) + (1)) < (_0_n)) && ((((t)[(_5_L) + (1)]) === (43)) || (((t)[(_5_L) + (1)]) === (45)))) ? ((_5_L) + (2)) : ((_5_L) + (1)))));
      if (_6_expm) {
        let _rhs2 = false;
        let _rhs3 = 0;
        ok = _rhs2;
        p = _rhs3;
        return [ok, p];
      }
      let _8_lead0;
      _8_lead0 = ((t)[_2_k]) === (48);
      if (_4_hasFrac) {
        let _9_lastNz;
        _9_lastNz = ((t)[(_5_L) - (1)]) !== (48);
        if (!(_9_lastNz)) {
          let _rhs4 = false;
          let _rhs5 = 0;
          ok = _rhs4;
          p = _rhs5;
          return [ok, p];
        }
        if (!(_8_lead0)) {
          let _10_sig;
          _10_sig = ((_3_e) - (_2_k)) + (((_5_L) - (_3_e)) - (1));
          if ((_10_sig) > (15)) {
            let _rhs6 = false;
            let _rhs7 = 0;
            ok = _rhs6;
            p = _rhs7;
            return [ok, p];
          }
          let _rhs8 = true;
          let _rhs9 = _5_L;
          ok = _rhs8;
          p = _rhs9;
          return [ok, p];
        } else {
          let _11_z;
          _11_z = 0;
          let _12_fl;
          _12_fl = ((_5_L) - (_3_e)) - (1);
          while (((_11_z) < (_12_fl)) && (((t)[((_3_e) + (1)) + (_11_z)]) === (48))) {
            _11_z = (_11_z) + (1);
          }
          let _13_sig;
          _13_sig = (_12_fl) - (_11_z);
          let _14_magOk;
          _14_magOk = (_11_z) < (6);
          if (((_13_sig) > (15)) || (!(_14_magOk))) {
            let _rhs10 = false;
            let _rhs11 = 0;
            ok = _rhs10;
            p = _rhs11;
            return [ok, p];
          }
          let _rhs12 = true;
          let _rhs13 = _5_L;
          ok = _rhs12;
          p = _rhs13;
          return [ok, p];
        }
      } else {
        if (_8_lead0) {
          if (_1_neg) {
            let _rhs14 = false;
            let _rhs15 = 0;
            ok = _rhs14;
            p = _rhs15;
            return [ok, p];
          }
          let _rhs16 = true;
          let _rhs17 = _5_L;
          ok = _rhs16;
          p = _rhs17;
          return [ok, p];
        }
        let _15_c;
        _15_c = (_3_e) - (_2_k);
        if ((_15_c) >= (17)) {
          let _rhs18 = false;
          let _rhs19 = 0;
          ok = _rhs18;
          p = _rhs19;
          return [ok, p];
        }
        let _16_lim;
        if ((_15_c) < (15)) {
          _16_lim = _15_c;
        } else {
          _16_lim = 15;
        }
        let _17_v;
        _17_v = 0;
        let _18_q;
        _18_q = 0;
        while ((_18_q) < (_16_lim)) {
          let _19_dg;
          _19_dg = (t)[(_2_k) + (_18_q)];
          _17_v = ((_17_v) * (10)) + ((_19_dg) - (48));
          _18_q = (_18_q) + (1);
        }
        if ((_15_c) <= (15)) {
          let _rhs20 = true;
          let _rhs21 = _5_L;
          ok = _rhs20;
          p = _rhs21;
          return [ok, p];
        }
        let _20_k15;
        _20_k15 = (_2_k) + (15);
        let _21_dl;
        _21_dl = (t)[_20_k15];
        let _22_last;
        _22_last = (_21_dl) - (48);
        let _23_big;
        _23_big = ((_17_v) > (900719925474099)) || (((_17_v) === (900719925474099)) && ((_22_last) > (1)));
        if (_23_big) {
          let _rhs22 = false;
          let _rhs23 = 0;
          ok = _rhs22;
          p = _rhs23;
          return [ok, p];
        }
        let _rhs24 = true;
        let _rhs25 = _5_L;
        ok = _rhs24;
        p = _rhs25;
        return [ok, p];
      }
      return [ok, p];
    }
    static HexDH(c) {
      if (((48) <= (c)) && ((c) <= (57))) {
        return (c) - (48);
      } else if (((97) <= (c)) && ((c) <= (102))) {
        return (c) - (87);
      } else if (((65) <= (c)) && ((c) <= (70))) {
        return (c) - (55);
      } else {
        return -1;
      }
    };
    static Hex4N(t, i) {
      let h = 0;
      if (((i) + (4)) > ((t).length)) {
        h = -1;
        return h;
      }
      let _0_a;
      _0_a = Fast.__default.HexDH((t)[i]);
      let _1_b;
      _1_b = Fast.__default.HexDH((t)[(i) + (1)]);
      let _2_c;
      _2_c = Fast.__default.HexDH((t)[(i) + (2)]);
      let _3_d;
      _3_d = Fast.__default.HexDH((t)[(i) + (3)]);
      if (((((_0_a) < (0)) || ((_1_b) < (0))) || ((_2_c) < (0))) || ((_3_d) < (0))) {
        h = -1;
        return h;
      }
      h = ((((((_0_a) * (16)) + (_1_b)) * (16)) + (_2_c)) * (16)) + (_3_d);
      return h;
      return h;
    }
    static StrM(t, ar, i, cur) {
      let ok = false;
      let p = 0;
      let c = 0;
      let _0_k;
      _0_k = i;
      c = cur;
      let _1_n;
      _1_n = (t).length;
      while (true) {
        if ((_0_k) >= (_1_n)) {
          let _rhs0 = false;
          let _rhs1 = 0;
          let _rhs2 = 0;
          ok = _rhs0;
          p = _rhs1;
          c = _rhs2;
          return [ok, p, c];
        }
        let _2_x;
        _2_x = (t)[_0_k];
        if ((_2_x) === (34)) {
          let _rhs3 = true;
          let _rhs4 = (_0_k) + (1);
          let _rhs5 = c;
          ok = _rhs3;
          p = _rhs4;
          c = _rhs5;
          return [ok, p, c];
        }
        if ((_2_x) < (32)) {
          let _rhs6 = false;
          let _rhs7 = 0;
          let _rhs8 = 0;
          ok = _rhs6;
          p = _rhs7;
          c = _rhs8;
          return [ok, p, c];
        }
        let _3_v = 0;
        let _4_adv = 0;
        if ((_2_x) === (92)) {
          if (((_0_k) + (1)) >= (_1_n)) {
            let _rhs9 = false;
            let _rhs10 = 0;
            let _rhs11 = 0;
            ok = _rhs9;
            p = _rhs10;
            c = _rhs11;
            return [ok, p, c];
          }
          let _5_e;
          _5_e = (t)[(_0_k) + (1)];
          if ((_5_e) === (34)) {
            _3_v = 34;
            _4_adv = 2;
          } else if ((_5_e) === (92)) {
            _3_v = 92;
            _4_adv = 2;
          } else if ((_5_e) === (47)) {
            _3_v = 47;
            _4_adv = 2;
          } else if ((_5_e) === (98)) {
            _3_v = 8;
            _4_adv = 2;
          } else if ((_5_e) === (102)) {
            _3_v = 12;
            _4_adv = 2;
          } else if ((_5_e) === (110)) {
            _3_v = 10;
            _4_adv = 2;
          } else if ((_5_e) === (114)) {
            _3_v = 13;
            _4_adv = 2;
          } else if ((_5_e) === (116)) {
            _3_v = 9;
            _4_adv = 2;
          } else if ((_5_e) === (117)) {
            let _6_h;
            let _out0;
            _out0 = Fast.__default.Hex4N(t, (_0_k) + (2));
            _6_h = _out0;
            if ((_6_h) < (0)) {
              let _rhs12 = false;
              let _rhs13 = 0;
              let _rhs14 = 0;
              ok = _rhs12;
              p = _rhs13;
              c = _rhs14;
              return [ok, p, c];
            }
            _3_v = _6_h;
            _4_adv = 6;
          } else {
            let _rhs15 = false;
            let _rhs16 = 0;
            let _rhs17 = 0;
            ok = _rhs15;
            p = _rhs16;
            c = _rhs17;
            return [ok, p, c];
          }
        } else {
          _3_v = _2_x;
          _4_adv = 1;
        }
        (ar)[(c)] = _3_v;
        c = (c) + (1);
        _0_k = (_0_k) + (_4_adv);
      }
      return [ok, p, c];
    }
    static V16M(ar, a, b) {
      let r = false;
      let _0_k;
      _0_k = a;
      while ((_0_k) < (b)) {
        let _1_x;
        _1_x = (ar)[_0_k];
        if (((55296) <= (_1_x)) && ((_1_x) <= (56319))) {
          if ((((_0_k) + (1)) < (b)) && (((56320) <= ((ar)[(_0_k) + (1)])) && (((ar)[(_0_k) + (1)]) <= (57343)))) {
            _0_k = (_0_k) + (2);
          } else {
            r = false;
            return r;
          }
        } else if (((56320) <= (_1_x)) && ((_1_x) <= (57343))) {
          r = false;
          return r;
        } else {
          _0_k = (_0_k) + (1);
        }
      }
      r = true;
      return r;
      return r;
    }
    static HStep(h, u, r) {
      let _0_hr = (h) * (r);
      return _dafny.EuclideanModuloNumber(((_0_hr) + (u)) + (1), Fast.__default.P);
    };
    static HashRange(ar, a, b, oid, r) {
      let h = 0;
      h = _dafny.EuclideanModuloNumber(oid, Fast.__default.P);
      let _0_k;
      _0_k = a;
      while ((_0_k) < (b)) {
        h = Fast.__default.HStep(h, (ar)[_0_k], r);
        _0_k = (_0_k) + (1);
      }
      return h;
    }
    static Lookup(bucket, ar, oid, a, len) {
      let found = false;
      let _0_q;
      _0_q = 0;
      let _1_nb;
      _1_nb = (bucket).length;
      while ((_0_q) < (_1_nb)) {
        let _2_e;
        _2_e = (bucket)[_0_q];
        if ((((_2_e).dtor_oid) === (oid)) && (((_2_e).dtor_len) === (len))) {
          let _3_w;
          _3_w = 0;
          while (((_3_w) < (len)) && (((ar)[((_2_e).dtor_off) + (_3_w)]) === ((ar)[(a) + (_3_w)]))) {
            _3_w = (_3_w) + (1);
          }
          if ((_3_w) === (len)) {
            found = true;
            return found;
          }
        }
        _0_q = (_0_q) + (1);
      }
      found = false;
      return found;
      return found;
    }
    static LitM(t, j) {
      let w = 0;
      let _0_n;
      _0_n = (t).length;
      let _1_isT;
      _1_isT = ((((((j) + (4)) <= (_0_n)) && (((t)[j]) === (116))) && (((t)[(j) + (1)]) === (114))) && (((t)[(j) + (2)]) === (117))) && (((t)[(j) + (3)]) === (101));
      let _2_isF;
      _2_isF = (((((((j) + (5)) <= (_0_n)) && (((t)[j]) === (102))) && (((t)[(j) + (1)]) === (97))) && (((t)[(j) + (2)]) === (108))) && (((t)[(j) + (3)]) === (115))) && (((t)[(j) + (4)]) === (101));
      let _3_isN;
      _3_isN = ((((((j) + (4)) <= (_0_n)) && (((t)[j]) === (110))) && (((t)[(j) + (1)]) === (117))) && (((t)[(j) + (2)]) === (108))) && (((t)[(j) + (3)]) === (108));
      if (_1_isT) {
        w = 1;
      } else if (_2_isF) {
        w = 2;
      } else if (_3_isN) {
        w = 3;
      } else {
        w = 0;
      }
      return w;
    }
    static ValueM(t, ar, tb, r, i, d, cur, nid) {
      let ok = false;
      let p = 0;
      let cur2 = 0;
      let nid2 = 0;
      let _0_n;
      _0_n = (t).length;
      let _1_j;
      let _out0;
      _out0 = Fast.__default.SkipWs(t, i);
      _1_j = _out0;
      if ((_1_j) >= (_0_n)) {
        let _rhs0 = false;
        let _rhs1 = 0;
        let _rhs2 = 0;
        let _rhs3 = 0;
        ok = _rhs0;
        p = _rhs1;
        cur2 = _rhs2;
        nid2 = _rhs3;
        return [ok, p, cur2, nid2];
      }
      let _2_c;
      _2_c = (t)[_1_j];
      if ((_2_c) === (123)) {
        if ((d) > (32)) {
          let _rhs4 = false;
          let _rhs5 = 0;
          let _rhs6 = 0;
          let _rhs7 = 0;
          ok = _rhs4;
          p = _rhs5;
          cur2 = _rhs6;
          nid2 = _rhs7;
          return [ok, p, cur2, nid2];
        }
        let _out1;
        let _out2;
        let _out3;
        let _out4;
        let _outcollector0 = Fast.__default.ObjM(t, ar, tb, r, (_1_j) + (1), d, cur, nid);
        _out1 = _outcollector0[0];
        _out2 = _outcollector0[1];
        _out3 = _outcollector0[2];
        _out4 = _outcollector0[3];
        ok = _out1;
        p = _out2;
        cur2 = _out3;
        nid2 = _out4;
      } else if ((_2_c) === (91)) {
        if ((d) > (32)) {
          let _rhs8 = false;
          let _rhs9 = 0;
          let _rhs10 = 0;
          let _rhs11 = 0;
          ok = _rhs8;
          p = _rhs9;
          cur2 = _rhs10;
          nid2 = _rhs11;
          return [ok, p, cur2, nid2];
        }
        let _out5;
        let _out6;
        let _out7;
        let _out8;
        let _outcollector1 = Fast.__default.ArrM(t, ar, tb, r, (_1_j) + (1), d, cur, nid);
        _out5 = _outcollector1[0];
        _out6 = _outcollector1[1];
        _out7 = _outcollector1[2];
        _out8 = _outcollector1[3];
        ok = _out5;
        p = _out6;
        cur2 = _out7;
        nid2 = _out8;
      } else if ((_2_c) === (34)) {
        let _3_okS;
        let _4_pS;
        let _5_c2;
        let _out9;
        let _out10;
        let _out11;
        let _outcollector2 = Fast.__default.StrM(t, ar, (_1_j) + (1), cur);
        _out9 = _outcollector2[0];
        _out10 = _outcollector2[1];
        _out11 = _outcollector2[2];
        _3_okS = _out9;
        _4_pS = _out10;
        _5_c2 = _out11;
        if (!(_3_okS)) {
          let _rhs12 = false;
          let _rhs13 = 0;
          let _rhs14 = 0;
          let _rhs15 = 0;
          ok = _rhs12;
          p = _rhs13;
          cur2 = _rhs14;
          nid2 = _rhs15;
          return [ok, p, cur2, nid2];
        }
        let _6_v16;
        let _out12;
        _out12 = Fast.__default.V16M(ar, cur, _5_c2);
        _6_v16 = _out12;
        if (!(_6_v16)) {
          let _rhs16 = false;
          let _rhs17 = 0;
          let _rhs18 = 0;
          let _rhs19 = 0;
          ok = _rhs16;
          p = _rhs17;
          cur2 = _rhs18;
          nid2 = _rhs19;
          return [ok, p, cur2, nid2];
        }
        let _rhs20 = true;
        let _rhs21 = _4_pS;
        let _rhs22 = _5_c2;
        let _rhs23 = nid;
        ok = _rhs20;
        p = _rhs21;
        cur2 = _rhs22;
        nid2 = _rhs23;
        return [ok, p, cur2, nid2];
      } else if (((_2_c) === (45)) || (((48) <= (_2_c)) && ((_2_c) <= (57)))) {
        let _7_okN;
        let _8_pN;
        let _out13;
        let _out14;
        let _outcollector3 = Fast.__default.NumM(t, _1_j);
        _out13 = _outcollector3[0];
        _out14 = _outcollector3[1];
        _7_okN = _out13;
        _8_pN = _out14;
        if (!(_7_okN)) {
          let _rhs24 = false;
          let _rhs25 = 0;
          let _rhs26 = 0;
          let _rhs27 = 0;
          ok = _rhs24;
          p = _rhs25;
          cur2 = _rhs26;
          nid2 = _rhs27;
          return [ok, p, cur2, nid2];
        }
        let _rhs28 = true;
        let _rhs29 = _8_pN;
        let _rhs30 = cur;
        let _rhs31 = nid;
        ok = _rhs28;
        p = _rhs29;
        cur2 = _rhs30;
        nid2 = _rhs31;
        return [ok, p, cur2, nid2];
      } else {
        let _9_w;
        let _out15;
        _out15 = Fast.__default.LitM(t, _1_j);
        _9_w = _out15;
        if ((_9_w) === (0)) {
          let _rhs32 = false;
          let _rhs33 = 0;
          let _rhs34 = 0;
          let _rhs35 = 0;
          ok = _rhs32;
          p = _rhs33;
          cur2 = _rhs34;
          nid2 = _rhs35;
          return [ok, p, cur2, nid2];
        }
        let _rhs36 = true;
        let _rhs37 = (((_9_w) === (2)) ? ((_1_j) + (5)) : ((_1_j) + (4)));
        let _rhs38 = cur;
        let _rhs39 = nid;
        ok = _rhs36;
        p = _rhs37;
        cur2 = _rhs38;
        nid2 = _rhs39;
        return [ok, p, cur2, nid2];
      }
      return [ok, p, cur2, nid2];
    }
    static ArrM(t, ar, tb, r, i, d, cur, nid) {
      let ok = false;
      let p = 0;
      let cur2 = 0;
      let nid2 = 0;
      let _0_n;
      _0_n = (t).length;
      let _1_j;
      let _out0;
      _out0 = Fast.__default.SkipWs(t, i);
      _1_j = _out0;
      if (((_1_j) < (_0_n)) && (((t)[_1_j]) === (93))) {
        let _rhs0 = true;
        let _rhs1 = (_1_j) + (1);
        let _rhs2 = cur;
        let _rhs3 = nid;
        ok = _rhs0;
        p = _rhs1;
        cur2 = _rhs2;
        nid2 = _rhs3;
        return [ok, p, cur2, nid2];
      }
      let _2_k;
      _2_k = i;
      cur2 = cur;
      nid2 = nid;
      L0: {
        while (true) {
          C0: {
            let _3_okV;
            let _4_q;
            let _5_c3;
            let _6_n3;
            let _out1;
            let _out2;
            let _out3;
            let _out4;
            let _outcollector0 = Fast.__default.ValueM(t, ar, tb, r, _2_k, (d) + (1), cur2, nid2);
            _out1 = _outcollector0[0];
            _out2 = _outcollector0[1];
            _out3 = _outcollector0[2];
            _out4 = _outcollector0[3];
            _3_okV = _out1;
            _4_q = _out2;
            _5_c3 = _out3;
            _6_n3 = _out4;
            if (!(_3_okV)) {
              let _rhs4 = false;
              let _rhs5 = 0;
              let _rhs6 = 0;
              let _rhs7 = 0;
              ok = _rhs4;
              p = _rhs5;
              cur2 = _rhs6;
              nid2 = _rhs7;
              return [ok, p, cur2, nid2];
            }
            let _rhs8 = _5_c3;
            let _rhs9 = _6_n3;
            cur2 = _rhs8;
            nid2 = _rhs9;
            let _7_j2;
            let _out5;
            _out5 = Fast.__default.SkipWs(t, _4_q);
            _7_j2 = _out5;
            if ((_7_j2) >= (_0_n)) {
              let _rhs10 = false;
              let _rhs11 = 0;
              let _rhs12 = 0;
              let _rhs13 = 0;
              ok = _rhs10;
              p = _rhs11;
              cur2 = _rhs12;
              nid2 = _rhs13;
              return [ok, p, cur2, nid2];
            }
            if (((t)[_7_j2]) === (44)) {
              _2_k = (_7_j2) + (1);
              break C0;
            }
            if (((t)[_7_j2]) === (93)) {
              let _rhs14 = true;
              let _rhs15 = (_7_j2) + (1);
              let _rhs16 = cur2;
              let _rhs17 = nid2;
              ok = _rhs14;
              p = _rhs15;
              cur2 = _rhs16;
              nid2 = _rhs17;
              return [ok, p, cur2, nid2];
            }
            let _rhs18 = false;
            let _rhs19 = 0;
            let _rhs20 = 0;
            let _rhs21 = 0;
            ok = _rhs18;
            p = _rhs19;
            cur2 = _rhs20;
            nid2 = _rhs21;
            return [ok, p, cur2, nid2];
          }
        }
      }
      return [ok, p, cur2, nid2];
    }
    static MemberM(t, ar, tb, r, k, d, cur, nid, oid) {
      let ok = false;
      let q = 0;
      let cur2 = 0;
      let nid2 = 0;
      let _0_n;
      _0_n = (t).length;
      let _1_m;
      _1_m = (tb).length;
      let _2_j;
      let _out0;
      _out0 = Fast.__default.SkipWs(t, k);
      _2_j = _out0;
      if (((_2_j) >= (_0_n)) || (((t)[_2_j]) !== (34))) {
        let _rhs0 = false;
        let _rhs1 = 0;
        let _rhs2 = 0;
        let _rhs3 = 0;
        ok = _rhs0;
        q = _rhs1;
        cur2 = _rhs2;
        nid2 = _rhs3;
        return [ok, q, cur2, nid2];
      }
      let _3_okS;
      let _4_pS;
      let _5_c2;
      let _out1;
      let _out2;
      let _out3;
      let _outcollector0 = Fast.__default.StrM(t, ar, (_2_j) + (1), cur);
      _out1 = _outcollector0[0];
      _out2 = _outcollector0[1];
      _out3 = _outcollector0[2];
      _3_okS = _out1;
      _4_pS = _out2;
      _5_c2 = _out3;
      if (!(_3_okS)) {
        let _rhs4 = false;
        let _rhs5 = 0;
        let _rhs6 = 0;
        let _rhs7 = 0;
        ok = _rhs4;
        q = _rhs5;
        cur2 = _rhs6;
        nid2 = _rhs7;
        return [ok, q, cur2, nid2];
      }
      let _6_v16;
      let _out4;
      _out4 = Fast.__default.V16M(ar, cur, _5_c2);
      _6_v16 = _out4;
      if (!(_6_v16)) {
        let _rhs8 = false;
        let _rhs9 = 0;
        let _rhs10 = 0;
        let _rhs11 = 0;
        ok = _rhs8;
        q = _rhs9;
        cur2 = _rhs10;
        nid2 = _rhs11;
        return [ok, q, cur2, nid2];
      }
      let _7_h;
      let _out5;
      _out5 = Fast.__default.HashRange(ar, cur, _5_c2, oid, r);
      _7_h = _out5;
      let _8_b;
      _8_b = _dafny.EuclideanModuloNumber(_7_h, _1_m);
      let _9_dup;
      let _out6;
      _out6 = Fast.__default.Lookup((tb)[_8_b], ar, oid, cur, (_5_c2) - (cur));
      _9_dup = _out6;
      if (_9_dup) {
        let _rhs12 = false;
        let _rhs13 = 0;
        let _rhs14 = 0;
        let _rhs15 = 0;
        ok = _rhs12;
        q = _rhs13;
        cur2 = _rhs14;
        nid2 = _rhs15;
        return [ok, q, cur2, nid2];
      }
      let _10_j2;
      let _out7;
      _out7 = Fast.__default.SkipWs(t, _4_pS);
      _10_j2 = _out7;
      if (((_10_j2) >= (_0_n)) || (((t)[_10_j2]) !== (58))) {
        let _rhs16 = false;
        let _rhs17 = 0;
        let _rhs18 = 0;
        let _rhs19 = 0;
        ok = _rhs16;
        q = _rhs17;
        cur2 = _rhs18;
        nid2 = _rhs19;
        return [ok, q, cur2, nid2];
      }
      (tb)[(_8_b)] = _dafny.Seq.Concat((tb)[_8_b], _dafny.Seq.of(Fast.Ent.create_Ent(oid, cur, (_5_c2) - (cur))));
      let _11_okV;
      let _12_q0;
      let _13_c3;
      let _14_n3;
      let _out8;
      let _out9;
      let _out10;
      let _out11;
      let _outcollector1 = Fast.__default.ValueM(t, ar, tb, r, (_10_j2) + (1), (d) + (1), _5_c2, (nid) + (1));
      _out8 = _outcollector1[0];
      _out9 = _outcollector1[1];
      _out10 = _outcollector1[2];
      _out11 = _outcollector1[3];
      _11_okV = _out8;
      _12_q0 = _out9;
      _13_c3 = _out10;
      _14_n3 = _out11;
      if (!(_11_okV)) {
        let _rhs20 = false;
        let _rhs21 = 0;
        let _rhs22 = 0;
        let _rhs23 = 0;
        ok = _rhs20;
        q = _rhs21;
        cur2 = _rhs22;
        nid2 = _rhs23;
        return [ok, q, cur2, nid2];
      }
      let _rhs24 = true;
      let _rhs25 = _12_q0;
      let _rhs26 = _13_c3;
      let _rhs27 = _14_n3;
      ok = _rhs24;
      q = _rhs25;
      cur2 = _rhs26;
      nid2 = _rhs27;
      return [ok, q, cur2, nid2];
      return [ok, q, cur2, nid2];
    }
    static ObjM(t, ar, tb, r, i, d, cur, nid) {
      let ok = false;
      let p = 0;
      let cur2 = 0;
      let nid2 = 0;
      let _0_n;
      _0_n = (t).length;
      let _1_j0;
      let _out0;
      _out0 = Fast.__default.SkipWs(t, i);
      _1_j0 = _out0;
      if (((_1_j0) < (_0_n)) && (((t)[_1_j0]) === (125))) {
        let _rhs0 = true;
        let _rhs1 = (_1_j0) + (1);
        let _rhs2 = cur;
        let _rhs3 = nid;
        ok = _rhs0;
        p = _rhs1;
        cur2 = _rhs2;
        nid2 = _rhs3;
        return [ok, p, cur2, nid2];
      }
      let _2_oid;
      _2_oid = nid;
      let _3_k;
      _3_k = i;
      cur2 = cur;
      nid2 = (nid) + (1);
      L1: {
        while (true) {
          C1: {
            let _4_okM;
            let _5_q;
            let _6_c3;
            let _7_n3;
            let _out1;
            let _out2;
            let _out3;
            let _out4;
            let _outcollector0 = Fast.__default.MemberM(t, ar, tb, r, _3_k, d, cur2, nid2, _2_oid);
            _out1 = _outcollector0[0];
            _out2 = _outcollector0[1];
            _out3 = _outcollector0[2];
            _out4 = _outcollector0[3];
            _4_okM = _out1;
            _5_q = _out2;
            _6_c3 = _out3;
            _7_n3 = _out4;
            if (!(_4_okM)) {
              let _rhs4 = false;
              let _rhs5 = 0;
              let _rhs6 = 0;
              let _rhs7 = 0;
              ok = _rhs4;
              p = _rhs5;
              cur2 = _rhs6;
              nid2 = _rhs7;
              return [ok, p, cur2, nid2];
            }
            let _rhs8 = _6_c3;
            let _rhs9 = _7_n3;
            cur2 = _rhs8;
            nid2 = _rhs9;
            let _8_j3;
            let _out5;
            _out5 = Fast.__default.SkipWs(t, _5_q);
            _8_j3 = _out5;
            if ((_8_j3) >= (_0_n)) {
              let _rhs10 = false;
              let _rhs11 = 0;
              let _rhs12 = 0;
              let _rhs13 = 0;
              ok = _rhs10;
              p = _rhs11;
              cur2 = _rhs12;
              nid2 = _rhs13;
              return [ok, p, cur2, nid2];
            }
            if (((t)[_8_j3]) === (44)) {
              _3_k = (_8_j3) + (1);
              break C1;
            }
            if (((t)[_8_j3]) === (125)) {
              let _rhs14 = true;
              let _rhs15 = (_8_j3) + (1);
              let _rhs16 = cur2;
              let _rhs17 = nid2;
              ok = _rhs14;
              p = _rhs15;
              cur2 = _rhs16;
              nid2 = _rhs17;
              return [ok, p, cur2, nid2];
            }
            let _rhs18 = false;
            let _rhs19 = 0;
            let _rhs20 = 0;
            let _rhs21 = 0;
            ok = _rhs18;
            p = _rhs19;
            cur2 = _rhs20;
            nid2 = _rhs21;
            return [ok, p, cur2, nid2];
          }
        }
      }
      return [ok, p, cur2, nid2];
    }
    static AcceptsU(t, seed) {
      let _hresult = false;
      if ((Json.__default.MaxBytes).isLessThan(new BigNumber((t).length))) {
        _hresult = false;
        return _hresult;
      }
      let _0_u8;
      let _out0;
      _out0 = Fast.__default.Utf8LenN(t);
      _0_u8 = _out0;
      if ((_0_u8) > ((Json.__default.MaxBytes).toNumber())) {
        _hresult = false;
        return _hresult;
      }
      let _1_n;
      _1_n = (t).length;
      let _2_ar;
      let _nw0 = Array((BigNumber(_1_n)).toNumber()).fill(0);
      _2_ar = _nw0;
      let _3_m;
      _3_m = (_dafny.EuclideanDivisionNumber(_1_n, 8)) + (16);
      let _4_tb;
      let _nw1 = Array((BigNumber(_3_m)).toNumber()).fill(_dafny.Seq.of());
      _4_tb = _nw1;
      let _5_empty;
      _5_empty = _dafny.Seq.of();
      let _6_b;
      _6_b = 0;
      while ((_6_b) < (_3_m)) {
        (_4_tb)[(_6_b)] = _5_empty;
        _6_b = (_6_b) + (1);
      }
      let _7_ok;
      let _8_p;
      let _9_c;
      let _10_nid;
      let _out1;
      let _out2;
      let _out3;
      let _out4;
      let _outcollector0 = Fast.__default.ValueM(t, _2_ar, _4_tb, _dafny.EuclideanModuloNumber(seed, Fast.__default.P), 0, 1, 0, 0);
      _out1 = _outcollector0[0];
      _out2 = _outcollector0[1];
      _out3 = _outcollector0[2];
      _out4 = _outcollector0[3];
      _7_ok = _out1;
      _8_p = _out2;
      _9_c = _out3;
      _10_nid = _out4;
      if (!(_7_ok)) {
        _hresult = false;
        return _hresult;
      }
      let _11_q;
      let _out5;
      _out5 = Fast.__default.SkipWs(t, _8_p);
      _11_q = _out5;
      _hresult = (_11_q) === (_1_n);
      return _hresult;
      return _hresult;
    }
    static get P() {
      return 67108859;
    };
  };

  $module.U16 = class U16 {
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
      let _0_x = new BigNumber(__source);
      return ((_dafny.ZERO).isLessThanOrEqualTo(_0_x)) && ((_0_x).isLessThan(new BigNumber(65536)));
    }
  };

  $module.N = class N {
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
      let _1_x = new BigNumber(__source);
      return ((_dafny.ZERO).isLessThanOrEqualTo(_1_x)) && ((_1_x).isLessThan(new BigNumber("9007199254740992")));
    }
  };

  $module.Hx = class Hx {
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
      let _2_x = new BigNumber(__source);
      return ((new BigNumber(-1)).isLessThanOrEqualTo(_2_x)) && ((_2_x).isLessThan(new BigNumber(16)));
    }
  };

  $module.H4 = class H4 {
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
      let _3_x = new BigNumber(__source);
      return ((new BigNumber(-1)).isLessThanOrEqualTo(_3_x)) && ((_3_x).isLessThan(new BigNumber(65536)));
    }
  };

  $module.Ent = class Ent {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Ent(oid, off, len) {
      let $dt = new Ent(0);
      $dt.oid = oid;
      $dt.off = off;
      $dt.len = len;
      return $dt;
    }
    get is_Ent() { return this.$tag === 0; }
    get dtor_oid() { return this.oid; }
    get dtor_off() { return this.off; }
    get dtor_len() { return this.len; }
    toString() {
      if (this.$tag === 0) {
        return "Fast.Ent.Ent" + "(" + _dafny.toString(this.oid) + ", " + _dafny.toString(this.off) + ", " + _dafny.toString(this.len) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.oid === other.oid && this.off === other.off && this.len === other.len;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Fast.Ent.create_Ent(0, 0, 0);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Ent.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module Fast
let FastP = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "FastP._default";
    }
    _parentTraits() {
      return [];
    }
    static Room(buf, n, k) {
      let ok = false;
      let b2 = [];
      let _0_len;
      _0_len = (buf).length;
      if (((n) + (k)) <= (_0_len)) {
        let _rhs0 = true;
        let _rhs1 = buf;
        ok = _rhs0;
        b2 = _rhs1;
        return [ok, b2];
      }
      if (((n) + (k)) > (FastP.__default.LIMIT)) {
        let _rhs2 = false;
        let _rhs3 = buf;
        ok = _rhs2;
        b2 = _rhs3;
        return [ok, b2];
      }
      let _1_cap;
      _1_cap = (((2) * (_0_len)) + (k)) + (16);
      if ((_1_cap) > (FastP.__default.LIMIT)) {
        _1_cap = FastP.__default.LIMIT;
      }
      let _nw0 = Array((BigNumber(_1_cap)).toNumber()).fill(0);
      b2 = _nw0;
      let _2_i;
      _2_i = 0;
      while ((_2_i) < (n)) {
        (b2)[(_2_i)] = (buf)[_2_i];
        _2_i = (_2_i) + (1);
      }
      let _rhs4 = true;
      let _rhs5 = b2;
      ok = _rhs4;
      b2 = _rhs5;
      return [ok, b2];
      return [ok, b2];
    }
    static PutSeq(buf, n, x) {
      let ok = false;
      let b2 = [];
      let n2 = 0;
      let _out0;
      let _out1;
      let _outcollector0 = FastP.__default.Room(buf, n, (x).length);
      _out0 = _outcollector0[0];
      _out1 = _outcollector0[1];
      ok = _out0;
      b2 = _out1;
      n2 = n;
      if (!(ok)) {
        return [ok, b2, n2];
      }
      let _0_i;
      _0_i = 0;
      while ((_0_i) < ((x).length)) {
        (b2)[(n2)] = (x)[_0_i];
        n2 = (n2) + (1);
        _0_i = (_0_i) + (1);
      }
      return [ok, b2, n2];
    }
    static Put1(buf, n, x) {
      let ok = false;
      let b2 = [];
      let n2 = 0;
      let _out0;
      let _out1;
      let _outcollector0 = FastP.__default.Room(buf, n, 1);
      _out0 = _outcollector0[0];
      _out1 = _outcollector0[1];
      ok = _out0;
      b2 = _out1;
      n2 = n;
      if (!(ok)) {
        return [ok, b2, n2];
      }
      (b2)[(n)] = x;
      n2 = (n) + (1);
      return [ok, b2, n2];
    }
    static Put2(buf, n, x, y) {
      let ok = false;
      let b2 = [];
      let n2 = 0;
      let _out0;
      let _out1;
      let _outcollector0 = FastP.__default.Room(buf, n, 2);
      _out0 = _outcollector0[0];
      _out1 = _outcollector0[1];
      ok = _out0;
      b2 = _out1;
      n2 = n;
      if (!(ok)) {
        return [ok, b2, n2];
      }
      (b2)[(n)] = x;
      let _index0 = (n) + (1);
      (b2)[_index0] = y;
      n2 = (n) + (2);
      return [ok, b2, n2];
    }
    static DigM(v, buf, n) {
      let ok = false;
      let b2 = [];
      let n2 = 0;
      let _out0;
      let _out1;
      let _outcollector0 = FastP.__default.Room(buf, n, FastP.__default.DigLen(v));
      _out0 = _outcollector0[0];
      _out1 = _outcollector0[1];
      ok = _out0;
      b2 = _out1;
      n2 = n;
      if (!(ok)) {
        return [ok, b2, n2];
      }
      let _out2;
      _out2 = FastP.__default.DigW(v, b2, n);
      n2 = _out2;
      return [ok, b2, n2];
    }
    static DigW(v, b, n) {
      let n2 = 0;
      let _0_m;
      _0_m = n;
      if ((v) >= (10)) {
        let _out0;
        _out0 = FastP.__default.DigW(_dafny.EuclideanDivisionNumber(v, 10), b, n);
        _0_m = _out0;
      }
      let _1_x;
      _1_x = (48) + (_dafny.EuclideanModuloNumber(v, 10));
      (b)[(_0_m)] = _1_x;
      n2 = (_0_m) + (1);
      return n2;
      return n2;
    }
    static DigLen(v) {
      let _0___accumulator = 0;
      TAIL_CALL_START: while (true) {
        if ((v) < (10)) {
          return (1) + (_0___accumulator);
        } else {
          _0___accumulator = (1) + (_0___accumulator);
          let _in0 = _dafny.EuclideanDivisionNumber(v, 10);
          v = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static V16S(s) {
      let r = false;
      let _0_k;
      _0_k = 0;
      let _1_n;
      _1_n = (s).length;
      while ((_0_k) < (_1_n)) {
        let _2_x;
        _2_x = (s)[_0_k];
        if (((55296) <= (_2_x)) && ((_2_x) <= (56319))) {
          if ((((_0_k) + (1)) < (_1_n)) && (((56320) <= ((s)[(_0_k) + (1)])) && (((s)[(_0_k) + (1)]) <= (57343)))) {
            _0_k = (_0_k) + (2);
          } else {
            r = false;
            return r;
          }
        } else if (((56320) <= (_2_x)) && ((_2_x) <= (57343))) {
          r = false;
          return r;
        } else {
          _0_k = (_0_k) + (1);
        }
      }
      r = true;
      return r;
      return r;
    }
    static HexLU(v) {
      if ((v) < (10)) {
        return (48) + (v);
      } else {
        return (97) + ((v) - (10));
      }
    };
    static BodyM(s, buf, n) {
      let ok = false;
      let b2 = [];
      let n2 = 0;
      let _rhs0 = buf;
      let _rhs1 = n;
      b2 = _rhs0;
      n2 = _rhs1;
      let _0_q;
      _0_q = 0;
      let _1_len;
      _1_len = (s).length;
      while ((_0_q) < (_1_len)) {
        let _2_x;
        _2_x = (s)[_0_q];
        let _3_r = false;
        if ((((b2).length) - (n2)) < (6)) {
          let _out0;
          let _out1;
          let _outcollector0 = FastP.__default.Room(b2, n2, 6);
          _out0 = _outcollector0[0];
          _out1 = _outcollector0[1];
          _3_r = _out0;
          b2 = _out1;
          if (!(_3_r)) {
            let _rhs2 = false;
            let _rhs3 = b2;
            let _rhs4 = n2;
            ok = _rhs2;
            b2 = _rhs3;
            n2 = _rhs4;
            return [ok, b2, n2];
          }
        }
        if ((_2_x) === (34)) {
          (b2)[(n2)] = 92;
          let _index0 = (n2) + (1);
          (b2)[_index0] = 34;
          n2 = (n2) + (2);
        } else if ((_2_x) === (92)) {
          (b2)[(n2)] = 92;
          let _index1 = (n2) + (1);
          (b2)[_index1] = 92;
          n2 = (n2) + (2);
        } else if ((_2_x) === (8)) {
          (b2)[(n2)] = 92;
          let _index2 = (n2) + (1);
          (b2)[_index2] = 98;
          n2 = (n2) + (2);
        } else if ((_2_x) === (12)) {
          (b2)[(n2)] = 92;
          let _index3 = (n2) + (1);
          (b2)[_index3] = 102;
          n2 = (n2) + (2);
        } else if ((_2_x) === (10)) {
          (b2)[(n2)] = 92;
          let _index4 = (n2) + (1);
          (b2)[_index4] = 110;
          n2 = (n2) + (2);
        } else if ((_2_x) === (13)) {
          (b2)[(n2)] = 92;
          let _index5 = (n2) + (1);
          (b2)[_index5] = 114;
          n2 = (n2) + (2);
        } else if ((_2_x) === (9)) {
          (b2)[(n2)] = 92;
          let _index6 = (n2) + (1);
          (b2)[_index6] = 116;
          n2 = (n2) + (2);
        } else if ((_2_x) < (32)) {
          let _4_h;
          _4_h = FastP.__default.HexLU(_dafny.EuclideanDivisionNumber(_2_x, 16));
          let _5_l;
          _5_l = FastP.__default.HexLU(_dafny.EuclideanModuloNumber(_2_x, 16));
          (b2)[(n2)] = 92;
          let _index7 = (n2) + (1);
          (b2)[_index7] = 117;
          let _index8 = (n2) + (2);
          (b2)[_index8] = 48;
          let _index9 = (n2) + (3);
          (b2)[_index9] = 48;
          let _index10 = (n2) + (4);
          (b2)[_index10] = _4_h;
          let _index11 = (n2) + (5);
          (b2)[_index11] = _5_l;
          n2 = (n2) + (6);
        } else {
          (b2)[(n2)] = _2_x;
          n2 = (n2) + (1);
        }
        _0_q = (_0_q) + (1);
      }
      let _rhs5 = true;
      let _rhs6 = b2;
      let _rhs7 = n2;
      ok = _rhs5;
      b2 = _rhs6;
      n2 = _rhs7;
      return [ok, b2, n2];
      return [ok, b2, n2];
    }
    static PrintM(u, d, buf, n) {
      let st = FastP.St.Default();
      let b2 = [];
      let n2 = 0;
      let _0_ok = false;
      let _source0 = u;
      Lmatch0: {
        {
          if (_source0.is_UNull) {
            let _out0;
            let _out1;
            let _out2;
            let _outcollector0 = FastP.__default.PutSeq(buf, n, _dafny.Seq.of(110, 117, 108, 108));
            _out0 = _outcollector0[0];
            _out1 = _outcollector0[1];
            _out2 = _outcollector0[2];
            _0_ok = _out0;
            b2 = _out1;
            n2 = _out2;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_UBool) {
            let _1_bv = (_source0).b;
            if (_1_bv) {
              let _out3;
              let _out4;
              let _out5;
              let _outcollector1 = FastP.__default.PutSeq(buf, n, _dafny.Seq.of(116, 114, 117, 101));
              _out3 = _outcollector1[0];
              _out4 = _outcollector1[1];
              _out5 = _outcollector1[2];
              _0_ok = _out3;
              b2 = _out4;
              n2 = _out5;
            } else {
              let _out6;
              let _out7;
              let _out8;
              let _outcollector2 = FastP.__default.PutSeq(buf, n, _dafny.Seq.of(102, 97, 108, 115, 101));
              _out6 = _outcollector2[0];
              _out7 = _outcollector2[1];
              _out8 = _outcollector2[2];
              _0_ok = _out6;
              b2 = _out7;
              n2 = _out8;
            }
            break Lmatch0;
          }
        }
        {
          if (_source0.is_UInt) {
            let _2_iv = (_source0).n;
            let _out9;
            let _out10;
            let _out11;
            let _outcollector3 = FastP.__default.IntM(_2_iv, buf, n);
            _out9 = _outcollector3[0];
            _out10 = _outcollector3[1];
            _out11 = _outcollector3[2];
            _0_ok = _out9;
            b2 = _out10;
            n2 = _out11;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_UBig) {
            let _3_bv = (_source0).bn;
            if (!((((_dafny.ZERO).minus(Json.__default.MaxSafe)).isLessThanOrEqualTo(_3_bv)) && ((_3_bv).isLessThanOrEqualTo(Json.__default.MaxSafe)))) {
              let _rhs0 = FastP.St.create_Bad();
              let _rhs1 = buf;
              let _rhs2 = n;
              st = _rhs0;
              b2 = _rhs1;
              n2 = _rhs2;
              return [st, b2, n2];
            }
            let _out12;
            let _out13;
            let _out14;
            let _outcollector4 = FastP.__default.IntM((_3_bv).toNumber(), buf, n);
            _out12 = _outcollector4[0];
            _out13 = _outcollector4[1];
            _out14 = _outcollector4[2];
            _0_ok = _out12;
            b2 = _out13;
            n2 = _out14;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_UDec) {
            let _4_neg = (_source0).neg;
            let _5_ip = (_source0).ip;
            let _6_fr = (_source0).fr;
            let _out15;
            let _out16;
            let _out17;
            let _outcollector5 = FastP.__default.DecM(_4_neg, _5_ip, _6_fr, buf, n);
            _out15 = _outcollector5[0];
            _out16 = _outcollector5[1];
            _out17 = _outcollector5[2];
            st = _out15;
            b2 = _out16;
            n2 = _out17;
            return [st, b2, n2];
            break Lmatch0;
          }
        }
        {
          if (_source0.is_UStr) {
            let _7_s = (_source0).s;
            if ((new BigNumber(FastP.__default.LIMIT)).isLessThanOrEqualTo(new BigNumber((_7_s).length))) {
              let _rhs3 = FastP.St.create_Exh();
              let _rhs4 = buf;
              let _rhs5 = n;
              st = _rhs3;
              b2 = _rhs4;
              n2 = _rhs5;
              return [st, b2, n2];
            }
            let _8_v16;
            let _out18;
            _out18 = FastP.__default.V16S(_7_s);
            _8_v16 = _out18;
            if (!(_8_v16)) {
              let _rhs6 = FastP.St.create_Bad();
              let _rhs7 = buf;
              let _rhs8 = n;
              st = _rhs6;
              b2 = _rhs7;
              n2 = _rhs8;
              return [st, b2, n2];
            }
            let _out19;
            let _out20;
            let _out21;
            let _outcollector6 = FastP.__default.Put1(buf, n, 34);
            _out19 = _outcollector6[0];
            _out20 = _outcollector6[1];
            _out21 = _outcollector6[2];
            _0_ok = _out19;
            b2 = _out20;
            n2 = _out21;
            if (!(_0_ok)) {
              let _rhs9 = FastP.St.create_Exh();
              let _rhs10 = b2;
              let _rhs11 = n2;
              st = _rhs9;
              b2 = _rhs10;
              n2 = _rhs11;
              return [st, b2, n2];
            }
            let _out22;
            let _out23;
            let _out24;
            let _outcollector7 = FastP.__default.BodyM(_7_s, b2, n2);
            _out22 = _outcollector7[0];
            _out23 = _outcollector7[1];
            _out24 = _outcollector7[2];
            _0_ok = _out22;
            b2 = _out23;
            n2 = _out24;
            if (!(_0_ok)) {
              let _rhs12 = FastP.St.create_Exh();
              let _rhs13 = b2;
              let _rhs14 = n2;
              st = _rhs12;
              b2 = _rhs13;
              n2 = _rhs14;
              return [st, b2, n2];
            }
            let _out25;
            let _out26;
            let _out27;
            let _outcollector8 = FastP.__default.Put1(b2, n2, 34);
            _out25 = _outcollector8[0];
            _out26 = _outcollector8[1];
            _out27 = _outcollector8[2];
            _0_ok = _out25;
            b2 = _out26;
            n2 = _out27;
            break Lmatch0;
          }
        }
        {
          if (_source0.is_UArr) {
            let _9_a = (_source0).a;
            let _out28;
            let _out29;
            let _out30;
            let _outcollector9 = FastP.__default.ArrPM(u, d, buf, n);
            _out28 = _outcollector9[0];
            _out29 = _outcollector9[1];
            _out30 = _outcollector9[2];
            st = _out28;
            b2 = _out29;
            n2 = _out30;
            return [st, b2, n2];
            break Lmatch0;
          }
        }
        {
          let _10_kv = (_source0).kv;
          let _out31;
          let _out32;
          let _out33;
          let _outcollector10 = FastP.__default.ObjPM(u, d, buf, n);
          _out31 = _outcollector10[0];
          _out32 = _outcollector10[1];
          _out33 = _outcollector10[2];
          st = _out31;
          b2 = _out32;
          n2 = _out33;
          return [st, b2, n2];
        }
      }
      if (_0_ok) {
        st = FastP.St.create_Done();
      } else {
        st = FastP.St.create_Exh();
      }
      return [st, b2, n2];
    }
    static IntM(iv, buf, n) {
      let ok = false;
      let b2 = [];
      let n2 = 0;
      let _0_a;
      if ((iv) < (0)) {
        _0_a = (0) - (iv);
      } else {
        _0_a = iv;
      }
      let _rhs0 = buf;
      let _rhs1 = n;
      b2 = _rhs0;
      n2 = _rhs1;
      ok = true;
      if ((((buf).length) - (n)) < (17)) {
        let _out0;
        let _out1;
        let _outcollector0 = FastP.__default.Room(buf, n, 17);
        _out0 = _outcollector0[0];
        _out1 = _outcollector0[1];
        ok = _out0;
        b2 = _out1;
        if (!(ok)) {
          return [ok, b2, n2];
        }
      }
      let _1_m;
      _1_m = n;
      if ((iv) < (0)) {
        (b2)[(n)] = 45;
        _1_m = (n) + (1);
      } else {
      }
      let _out2;
      _out2 = FastP.__default.DigW(_0_a, b2, _1_m);
      n2 = _out2;
      return [ok, b2, n2];
    }
    static DecM(neg, ip, fr, buf, n) {
      let st = FastP.St.Default();
      let b2 = [];
      let n2 = 0;
      if ((new BigNumber(FastP.__default.LIMIT)).isLessThanOrEqualTo(new BigNumber((fr).length))) {
        let _rhs0 = FastP.St.create_Exh();
        let _rhs1 = buf;
        let _rhs2 = n;
        st = _rhs0;
        b2 = _rhs1;
        n2 = _rhs2;
        return [st, b2, n2];
      }
      let _0_fl;
      _0_fl = (fr).length;
      if ((_0_fl) === (0)) {
        let _rhs3 = FastP.St.create_Bad();
        let _rhs4 = buf;
        let _rhs5 = n;
        st = _rhs3;
        b2 = _rhs4;
        n2 = _rhs5;
        return [st, b2, n2];
      }
      let _1_q;
      _1_q = 0;
      while (((_1_q) < (_0_fl)) && (((fr)[_1_q]) <= (9))) {
        _1_q = (_1_q) + (1);
      }
      if ((_1_q) < (_0_fl)) {
        let _rhs6 = FastP.St.create_Bad();
        let _rhs7 = buf;
        let _rhs8 = n;
        st = _rhs6;
        b2 = _rhs7;
        n2 = _rhs8;
        return [st, b2, n2];
      }
      if (((fr)[(_0_fl) - (1)]) === (0)) {
        let _rhs9 = FastP.St.create_Bad();
        let _rhs10 = buf;
        let _rhs11 = n;
        st = _rhs9;
        b2 = _rhs10;
        n2 = _rhs11;
        return [st, b2, n2];
      }
      let _2_sig = 0;
      let _3_magOk = false;
      if ((ip) > (0)) {
        _2_sig = (FastP.__default.DigLen(ip)) + (_0_fl);
        _3_magOk = true;
      } else {
        let _4_z;
        _4_z = 0;
        while (((_4_z) < (_0_fl)) && (((fr)[_4_z]) === (0))) {
          _4_z = (_4_z) + (1);
        }
        _2_sig = (_0_fl) - (_4_z);
        _3_magOk = (_4_z) < (6);
      }
      if (((_2_sig) > (15)) || (!(_3_magOk))) {
        let _rhs12 = FastP.St.create_Bad();
        let _rhs13 = buf;
        let _rhs14 = n;
        st = _rhs12;
        b2 = _rhs13;
        n2 = _rhs14;
        return [st, b2, n2];
      }
      let _5_ok = false;
      if (neg) {
        let _out0;
        let _out1;
        let _out2;
        let _outcollector0 = FastP.__default.Put1(buf, n, 45);
        _out0 = _outcollector0[0];
        _out1 = _outcollector0[1];
        _out2 = _outcollector0[2];
        _5_ok = _out0;
        b2 = _out1;
        n2 = _out2;
        if (!(_5_ok)) {
          let _rhs15 = FastP.St.create_Exh();
          let _rhs16 = b2;
          let _rhs17 = n2;
          st = _rhs15;
          b2 = _rhs16;
          n2 = _rhs17;
          return [st, b2, n2];
        }
      } else {
        let _rhs18 = buf;
        let _rhs19 = n;
        b2 = _rhs18;
        n2 = _rhs19;
      }
      let _out3;
      let _out4;
      let _out5;
      let _outcollector1 = FastP.__default.DigM(ip, b2, n2);
      _out3 = _outcollector1[0];
      _out4 = _outcollector1[1];
      _out5 = _outcollector1[2];
      _5_ok = _out3;
      b2 = _out4;
      n2 = _out5;
      if (!(_5_ok)) {
        let _rhs20 = FastP.St.create_Exh();
        let _rhs21 = b2;
        let _rhs22 = n2;
        st = _rhs20;
        b2 = _rhs21;
        n2 = _rhs22;
        return [st, b2, n2];
      }
      let _out6;
      let _out7;
      let _out8;
      let _outcollector2 = FastP.__default.Put1(b2, n2, 46);
      _out6 = _outcollector2[0];
      _out7 = _outcollector2[1];
      _out8 = _outcollector2[2];
      _5_ok = _out6;
      b2 = _out7;
      n2 = _out8;
      if (!(_5_ok)) {
        let _rhs23 = FastP.St.create_Exh();
        let _rhs24 = b2;
        let _rhs25 = n2;
        st = _rhs23;
        b2 = _rhs24;
        n2 = _rhs25;
        return [st, b2, n2];
      }
      let _6_r = false;
      let _out9;
      let _out10;
      let _outcollector3 = FastP.__default.Room(b2, n2, 0);
      _out9 = _outcollector3[0];
      _out10 = _outcollector3[1];
      _6_r = _out9;
      b2 = _out10;
      let _7_i;
      _7_i = 0;
      while ((_7_i) < (_0_fl)) {
        let _out11;
        let _out12;
        let _outcollector4 = FastP.__default.Room(b2, n2, 1);
        _out11 = _outcollector4[0];
        _out12 = _outcollector4[1];
        _6_r = _out11;
        b2 = _out12;
        if (!(_6_r)) {
          let _rhs26 = FastP.St.create_Exh();
          let _rhs27 = b2;
          let _rhs28 = n2;
          st = _rhs26;
          b2 = _rhs27;
          n2 = _rhs28;
          return [st, b2, n2];
        }
        (b2)[(n2)] = (48) + ((fr)[_7_i]);
        n2 = (n2) + (1);
        _7_i = (_7_i) + (1);
      }
      let _rhs29 = FastP.St.create_Done();
      let _rhs30 = b2;
      let _rhs31 = n2;
      st = _rhs29;
      b2 = _rhs30;
      n2 = _rhs31;
      return [st, b2, n2];
      return [st, b2, n2];
    }
    static ArrPM(u, d, buf, n) {
      let st = FastP.St.Default();
      let b2 = [];
      let n2 = 0;
      let _0_a;
      _0_a = (u).dtor_a;
      if ((d) > (32)) {
        let _rhs0 = FastP.St.create_Bad();
        let _rhs1 = buf;
        let _rhs2 = n;
        st = _rhs0;
        b2 = _rhs1;
        n2 = _rhs2;
        return [st, b2, n2];
      }
      if ((new BigNumber(FastP.__default.LIMIT)).isLessThanOrEqualTo(new BigNumber((_0_a).length))) {
        let _rhs3 = FastP.St.create_Exh();
        let _rhs4 = buf;
        let _rhs5 = n;
        st = _rhs3;
        b2 = _rhs4;
        n2 = _rhs5;
        return [st, b2, n2];
      }
      let _1_len;
      _1_len = (_0_a).length;
      let _2_ok = false;
      let _out0;
      let _out1;
      let _out2;
      let _outcollector0 = FastP.__default.Put1(buf, n, 91);
      _out0 = _outcollector0[0];
      _out1 = _outcollector0[1];
      _out2 = _outcollector0[2];
      _2_ok = _out0;
      b2 = _out1;
      n2 = _out2;
      if (!(_2_ok)) {
        let _rhs6 = FastP.St.create_Exh();
        let _rhs7 = b2;
        let _rhs8 = n2;
        st = _rhs6;
        b2 = _rhs7;
        n2 = _rhs8;
        return [st, b2, n2];
      }
      let _3_q;
      _3_q = 0;
      while ((_3_q) < (_1_len)) {
        if ((_3_q) > (0)) {
          if ((((b2).length) - (n2)) < (1)) {
            let _out3;
            let _out4;
            let _outcollector1 = FastP.__default.Room(b2, n2, 1);
            _out3 = _outcollector1[0];
            _out4 = _outcollector1[1];
            _2_ok = _out3;
            b2 = _out4;
            if (!(_2_ok)) {
              let _rhs9 = FastP.St.create_Exh();
              let _rhs10 = b2;
              let _rhs11 = n2;
              st = _rhs9;
              b2 = _rhs10;
              n2 = _rhs11;
              return [st, b2, n2];
            }
          }
          (b2)[(n2)] = 44;
          n2 = (n2) + (1);
        }
        let _4_s = FastP.St.Default();
        let _out5;
        let _out6;
        let _out7;
        let _outcollector2 = FastP.__default.PrintM((_0_a)[_3_q], (d) + (1), b2, n2);
        _out5 = _outcollector2[0];
        _out6 = _outcollector2[1];
        _out7 = _outcollector2[2];
        _4_s = _out5;
        b2 = _out6;
        n2 = _out7;
        if ((_4_s).is_Bad) {
          let _rhs12 = FastP.St.create_Bad();
          let _rhs13 = b2;
          let _rhs14 = n2;
          st = _rhs12;
          b2 = _rhs13;
          n2 = _rhs14;
          return [st, b2, n2];
        }
        if ((_4_s).is_Exh) {
          let _rhs15 = FastP.St.create_Exh();
          let _rhs16 = b2;
          let _rhs17 = n2;
          st = _rhs15;
          b2 = _rhs16;
          n2 = _rhs17;
          return [st, b2, n2];
        }
        _3_q = (_3_q) + (1);
      }
      let _out8;
      let _out9;
      let _out10;
      let _outcollector3 = FastP.__default.Put1(b2, n2, 93);
      _out8 = _outcollector3[0];
      _out9 = _outcollector3[1];
      _out10 = _outcollector3[2];
      _2_ok = _out8;
      b2 = _out9;
      n2 = _out10;
      if (!(_2_ok)) {
        let _rhs18 = FastP.St.create_Exh();
        let _rhs19 = b2;
        let _rhs20 = n2;
        st = _rhs18;
        b2 = _rhs19;
        n2 = _rhs20;
        return [st, b2, n2];
      }
      let _rhs21 = FastP.St.create_Done();
      let _rhs22 = b2;
      let _rhs23 = n2;
      st = _rhs21;
      b2 = _rhs22;
      n2 = _rhs23;
      return [st, b2, n2];
      return [st, b2, n2];
    }
    static CpsM(s) {
      let a = [];
      let c = 0;
      let _0_n;
      _0_n = (s).length;
      let _nw0 = Array((BigNumber(_0_n)).toNumber()).fill(0);
      a = _nw0;
      c = 0;
      let _1_q;
      _1_q = 0;
      while ((_1_q) < (_0_n)) {
        let _2_x;
        _2_x = (s)[_1_q];
        if (((((55296) <= (_2_x)) && ((_2_x) <= (56319))) && (((_1_q) + (1)) < (_0_n))) && (((56320) <= ((s)[(_1_q) + (1)])) && (((s)[(_1_q) + (1)]) <= (57343)))) {
          let _3_cp;
          _3_cp = ((65536) + (((_2_x) - (55296)) * (1024))) + (((s)[(_1_q) + (1)]) - (56320));
          (a)[(c)] = _3_cp;
          c = (c) + (1);
          _1_q = (_1_q) + (2);
        } else {
          (a)[(c)] = _2_x;
          c = (c) + (1);
          _1_q = (_1_q) + (1);
        }
      }
      return [a, c];
    }
    static LessM(x, xn, y, yn) {
      let r = false;
      let _0_i;
      _0_i = 0;
      while ((((_0_i) < (xn)) && ((_0_i) < (yn))) && (((x)[_0_i]) === ((y)[_0_i]))) {
        _0_i = (_0_i) + (1);
      }
      if ((_0_i) === (yn)) {
        r = false;
        return r;
      }
      if ((_0_i) === (xn)) {
        r = true;
        return r;
      }
      r = ((x)[_0_i]) < ((y)[_0_i]);
      return r;
      return r;
    }
    static Merge(p, lo, mid, hi, tmp, cps) {
      let _0_i;
      let _1_j;
      let _2_k;
      let _rhs0 = lo;
      let _rhs1 = mid;
      let _rhs2 = lo;
      _0_i = _rhs0;
      _1_j = _rhs1;
      _2_k = _rhs2;
      while ((_2_k) < (hi)) {
        let _3_takeLeft = false;
        if ((_0_i) === (mid)) {
          _3_takeLeft = false;
        } else if ((_1_j) === (hi)) {
          _3_takeLeft = true;
        } else {
          let _4_cy;
          _4_cy = (cps)[(p)[_1_j]];
          let _5_cx;
          _5_cx = (cps)[(p)[_0_i]];
          let _6_lt;
          let _out0;
          _out0 = FastP.__default.LessM((_4_cy).dtor_a, (_4_cy).dtor_c, (_5_cx).dtor_a, (_5_cx).dtor_c);
          _6_lt = _out0;
          _3_takeLeft = !(_6_lt);
        }
        let _7_x;
        if (_3_takeLeft) {
          _7_x = (p)[_0_i];
        } else {
          _7_x = (p)[_1_j];
        }
        (tmp)[(_2_k)] = _7_x;
        if (_3_takeLeft) {
          _0_i = (_0_i) + (1);
        } else {
          _1_j = (_1_j) + (1);
        }
        _2_k = (_2_k) + (1);
      }
      FastP.__default.CopyBack(p, tmp, lo, hi);
      return;
    }
    static CopyBack(p, tmp, lo, hi) {
      let _0_w;
      _0_w = lo;
      while ((_0_w) < (hi)) {
        (p)[(_0_w)] = (tmp)[_0_w];
        _0_w = (_0_w) + (1);
      }
      return;
    }
    static MSort(p, lo, hi, tmp, cps) {
      if (((hi) - (lo)) <= (1)) {
        return;
      }
      let _0_mid;
      _0_mid = (lo) + (_dafny.EuclideanDivisionNumber((hi) - (lo), 2));
      FastP.__default.MSort(p, lo, _0_mid, tmp, cps);
      FastP.__default.MSort(p, _0_mid, hi, tmp, cps);
      FastP.__default.Merge(p, lo, _0_mid, hi, tmp, cps);
      return;
    }
    static ObjPM(u, d, buf, n) {
      let st = FastP.St.Default();
      let b2 = [];
      let n2 = 0;
      let _0_kv;
      _0_kv = (u).dtor_kv;
      if ((d) > (32)) {
        let _rhs0 = FastP.St.create_Bad();
        let _rhs1 = buf;
        let _rhs2 = n;
        st = _rhs0;
        b2 = _rhs1;
        n2 = _rhs2;
        return [st, b2, n2];
      }
      if ((new BigNumber(FastP.__default.LIMIT)).isLessThanOrEqualTo(new BigNumber((_0_kv).length))) {
        let _rhs3 = FastP.St.create_Exh();
        let _rhs4 = buf;
        let _rhs5 = n;
        st = _rhs3;
        b2 = _rhs4;
        n2 = _rhs5;
        return [st, b2, n2];
      }
      let _1_cnt;
      _1_cnt = (_0_kv).length;
      let _2_cps;
      let _nw0 = Array((BigNumber(_1_cnt)).toNumber()).fill(FastP.CP.Default());
      _2_cps = _nw0;
      let _3_i;
      _3_i = 0;
      while ((_3_i) < (_1_cnt)) {
        let _4_key;
        _4_key = ((_0_kv)[_3_i]).dtor_k;
        if ((new BigNumber(FastP.__default.LIMIT)).isLessThanOrEqualTo(new BigNumber((_4_key).length))) {
          let _rhs6 = FastP.St.create_Exh();
          let _rhs7 = buf;
          let _rhs8 = n;
          st = _rhs6;
          b2 = _rhs7;
          n2 = _rhs8;
          return [st, b2, n2];
        }
        let _5_v16;
        let _out0;
        _out0 = FastP.__default.V16S(_4_key);
        _5_v16 = _out0;
        if (!(_5_v16)) {
          let _rhs9 = FastP.St.create_Bad();
          let _rhs10 = buf;
          let _rhs11 = n;
          st = _rhs9;
          b2 = _rhs10;
          n2 = _rhs11;
          return [st, b2, n2];
        }
        let _6_a;
        let _7_c;
        let _out1;
        let _out2;
        let _outcollector0 = FastP.__default.CpsM(_4_key);
        _out1 = _outcollector0[0];
        _out2 = _outcollector0[1];
        _6_a = _out1;
        _7_c = _out2;
        (_2_cps)[(_3_i)] = FastP.CP.create_CP(_6_a, _7_c);
        _3_i = (_3_i) + (1);
      }
      let _8_perm;
      let _nw1 = Array((BigNumber(_1_cnt)).toNumber()).fill(0);
      _8_perm = _nw1;
      let _9_tmp;
      let _nw2 = Array((BigNumber(_1_cnt)).toNumber()).fill(0);
      _9_tmp = _nw2;
      _3_i = 0;
      while ((_3_i) < (_1_cnt)) {
        (_8_perm)[(_3_i)] = _3_i;
        _3_i = (_3_i) + (1);
      }
      FastP.__default.MSort(_8_perm, 0, _1_cnt, _9_tmp, _2_cps);
      _3_i = 0;
      while (((_3_i) + (1)) < (_1_cnt)) {
        let _10_x;
        _10_x = (_2_cps)[(_8_perm)[_3_i]];
        let _11_y;
        _11_y = (_2_cps)[(_8_perm)[(_3_i) + (1)]];
        let _12_lt;
        let _out3;
        _out3 = FastP.__default.LessM((_10_x).dtor_a, (_10_x).dtor_c, (_11_y).dtor_a, (_11_y).dtor_c);
        _12_lt = _out3;
        if (!(_12_lt)) {
          let _rhs12 = FastP.St.create_Bad();
          let _rhs13 = buf;
          let _rhs14 = n;
          st = _rhs12;
          b2 = _rhs13;
          n2 = _rhs14;
          return [st, b2, n2];
        }
        _3_i = (_3_i) + (1);
      }
      let _13_ok = false;
      let _out4;
      let _out5;
      let _out6;
      let _outcollector1 = FastP.__default.Put1(buf, n, 123);
      _out4 = _outcollector1[0];
      _out5 = _outcollector1[1];
      _out6 = _outcollector1[2];
      _13_ok = _out4;
      b2 = _out5;
      n2 = _out6;
      if (!(_13_ok)) {
        let _rhs15 = FastP.St.create_Exh();
        let _rhs16 = b2;
        let _rhs17 = n2;
        st = _rhs15;
        b2 = _rhs16;
        n2 = _rhs17;
        return [st, b2, n2];
      }
      let _14_q;
      _14_q = 0;
      while ((_14_q) < (_1_cnt)) {
        let _15_idx;
        _15_idx = (_8_perm)[_14_q];
        if ((_14_q) > (0)) {
          let _out7;
          let _out8;
          let _out9;
          let _outcollector2 = FastP.__default.Put2(b2, n2, 44, 34);
          _out7 = _outcollector2[0];
          _out8 = _outcollector2[1];
          _out9 = _outcollector2[2];
          _13_ok = _out7;
          b2 = _out8;
          n2 = _out9;
          if (!(_13_ok)) {
            let _rhs18 = FastP.St.create_Exh();
            let _rhs19 = b2;
            let _rhs20 = n2;
            st = _rhs18;
            b2 = _rhs19;
            n2 = _rhs20;
            return [st, b2, n2];
          }
        } else {
          let _out10;
          let _out11;
          let _out12;
          let _outcollector3 = FastP.__default.Put1(b2, n2, 34);
          _out10 = _outcollector3[0];
          _out11 = _outcollector3[1];
          _out12 = _outcollector3[2];
          _13_ok = _out10;
          b2 = _out11;
          n2 = _out12;
          if (!(_13_ok)) {
            let _rhs21 = FastP.St.create_Exh();
            let _rhs22 = b2;
            let _rhs23 = n2;
            st = _rhs21;
            b2 = _rhs22;
            n2 = _rhs23;
            return [st, b2, n2];
          }
        }
        let _out13;
        let _out14;
        let _out15;
        let _outcollector4 = FastP.__default.BodyM(((_0_kv)[_15_idx]).dtor_k, b2, n2);
        _out13 = _outcollector4[0];
        _out14 = _outcollector4[1];
        _out15 = _outcollector4[2];
        _13_ok = _out13;
        b2 = _out14;
        n2 = _out15;
        if (!(_13_ok)) {
          let _rhs24 = FastP.St.create_Exh();
          let _rhs25 = b2;
          let _rhs26 = n2;
          st = _rhs24;
          b2 = _rhs25;
          n2 = _rhs26;
          return [st, b2, n2];
        }
        let _out16;
        let _out17;
        let _out18;
        let _outcollector5 = FastP.__default.Put2(b2, n2, 34, 58);
        _out16 = _outcollector5[0];
        _out17 = _outcollector5[1];
        _out18 = _outcollector5[2];
        _13_ok = _out16;
        b2 = _out17;
        n2 = _out18;
        if (!(_13_ok)) {
          let _rhs27 = FastP.St.create_Exh();
          let _rhs28 = b2;
          let _rhs29 = n2;
          st = _rhs27;
          b2 = _rhs28;
          n2 = _rhs29;
          return [st, b2, n2];
        }
        let _16_s = FastP.St.Default();
        let _out19;
        let _out20;
        let _out21;
        let _outcollector6 = FastP.__default.PrintM(((_0_kv)[_15_idx]).dtor_v, (d) + (1), b2, n2);
        _out19 = _outcollector6[0];
        _out20 = _outcollector6[1];
        _out21 = _outcollector6[2];
        _16_s = _out19;
        b2 = _out20;
        n2 = _out21;
        if ((_16_s).is_Bad) {
          let _rhs30 = FastP.St.create_Bad();
          let _rhs31 = b2;
          let _rhs32 = n2;
          st = _rhs30;
          b2 = _rhs31;
          n2 = _rhs32;
          return [st, b2, n2];
        }
        if ((_16_s).is_Exh) {
          let _rhs33 = FastP.St.create_Exh();
          let _rhs34 = b2;
          let _rhs35 = n2;
          st = _rhs33;
          b2 = _rhs34;
          n2 = _rhs35;
          return [st, b2, n2];
        }
        _14_q = (_14_q) + (1);
      }
      let _out22;
      let _out23;
      let _out24;
      let _outcollector7 = FastP.__default.Put1(b2, n2, 125);
      _out22 = _outcollector7[0];
      _out23 = _outcollector7[1];
      _out24 = _outcollector7[2];
      _13_ok = _out22;
      b2 = _out23;
      n2 = _out24;
      if (!(_13_ok)) {
        let _rhs36 = FastP.St.create_Exh();
        let _rhs37 = b2;
        let _rhs38 = n2;
        st = _rhs36;
        b2 = _rhs37;
        n2 = _rhs38;
        return [st, b2, n2];
      }
      let _rhs39 = FastP.St.create_Done();
      let _rhs40 = b2;
      let _rhs41 = n2;
      st = _rhs39;
      b2 = _rhs40;
      n2 = _rhs41;
      return [st, b2, n2];
      return [st, b2, n2];
    }
    static CanonU(u) {
      let st = FastP.St.Default();
      let b = [];
      let n = 0;
      let _0_buf;
      let _nw0 = Array((new BigNumber(64)).toNumber()).fill(0);
      _0_buf = _nw0;
      let _out0;
      let _out1;
      let _out2;
      let _outcollector0 = FastP.__default.PrintM(u, 1, _0_buf, 0);
      _out0 = _outcollector0[0];
      _out1 = _outcollector0[1];
      _out2 = _outcollector0[2];
      st = _out0;
      b = _out1;
      n = _out2;
      return [st, b, n];
    }
    static get LIMIT() {
      return 1099511627776;
    };
  };

  $module.I = class I {
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
      let _0_x = new BigNumber(__source);
      return ((new BigNumber(-9007199254740991)).isLessThanOrEqualTo(_0_x)) && ((_0_x).isLessThanOrEqualTo(new BigNumber(9007199254740991)));
    }
  };

  $module.JU = class JU {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_UNull() {
      let $dt = new JU(0);
      return $dt;
    }
    static create_UBool(b) {
      let $dt = new JU(1);
      $dt.b = b;
      return $dt;
    }
    static create_UInt(n) {
      let $dt = new JU(2);
      $dt.n = n;
      return $dt;
    }
    static create_UBig(bn) {
      let $dt = new JU(3);
      $dt.bn = bn;
      return $dt;
    }
    static create_UDec(neg, ip, fr) {
      let $dt = new JU(4);
      $dt.neg = neg;
      $dt.ip = ip;
      $dt.fr = fr;
      return $dt;
    }
    static create_UStr(s) {
      let $dt = new JU(5);
      $dt.s = s;
      return $dt;
    }
    static create_UArr(a) {
      let $dt = new JU(6);
      $dt.a = a;
      return $dt;
    }
    static create_UObj(kv) {
      let $dt = new JU(7);
      $dt.kv = kv;
      return $dt;
    }
    get is_UNull() { return this.$tag === 0; }
    get is_UBool() { return this.$tag === 1; }
    get is_UInt() { return this.$tag === 2; }
    get is_UBig() { return this.$tag === 3; }
    get is_UDec() { return this.$tag === 4; }
    get is_UStr() { return this.$tag === 5; }
    get is_UArr() { return this.$tag === 6; }
    get is_UObj() { return this.$tag === 7; }
    get dtor_b() { return this.b; }
    get dtor_n() { return this.n; }
    get dtor_bn() { return this.bn; }
    get dtor_neg() { return this.neg; }
    get dtor_ip() { return this.ip; }
    get dtor_fr() { return this.fr; }
    get dtor_s() { return this.s; }
    get dtor_a() { return this.a; }
    get dtor_kv() { return this.kv; }
    toString() {
      if (this.$tag === 0) {
        return "FastP.JU.UNull";
      } else if (this.$tag === 1) {
        return "FastP.JU.UBool" + "(" + _dafny.toString(this.b) + ")";
      } else if (this.$tag === 2) {
        return "FastP.JU.UInt" + "(" + _dafny.toString(this.n) + ")";
      } else if (this.$tag === 3) {
        return "FastP.JU.UBig" + "(" + _dafny.toString(this.bn) + ")";
      } else if (this.$tag === 4) {
        return "FastP.JU.UDec" + "(" + _dafny.toString(this.neg) + ", " + _dafny.toString(this.ip) + ", " + _dafny.toString(this.fr) + ")";
      } else if (this.$tag === 5) {
        return "FastP.JU.UStr" + "(" + _dafny.toString(this.s) + ")";
      } else if (this.$tag === 6) {
        return "FastP.JU.UArr" + "(" + _dafny.toString(this.a) + ")";
      } else if (this.$tag === 7) {
        return "FastP.JU.UObj" + "(" + _dafny.toString(this.kv) + ")";
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
        return other.$tag === 2 && this.n === other.n;
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.bn, other.bn);
      } else if (this.$tag === 4) {
        return other.$tag === 4 && this.neg === other.neg && this.ip === other.ip && _dafny.areEqual(this.fr, other.fr);
      } else if (this.$tag === 5) {
        return other.$tag === 5 && _dafny.areEqual(this.s, other.s);
      } else if (this.$tag === 6) {
        return other.$tag === 6 && _dafny.areEqual(this.a, other.a);
      } else if (this.$tag === 7) {
        return other.$tag === 7 && _dafny.areEqual(this.kv, other.kv);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return FastP.JU.create_UNull();
    }
    static Rtd() {
      return class {
        static get Default() {
          return JU.Default();
        }
      };
    }
  }

  $module.KU = class KU {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_KU(k, v) {
      let $dt = new KU(0);
      $dt.k = k;
      $dt.v = v;
      return $dt;
    }
    get is_KU() { return this.$tag === 0; }
    get dtor_k() { return this.k; }
    get dtor_v() { return this.v; }
    toString() {
      if (this.$tag === 0) {
        return "FastP.KU.KU" + "(" + _dafny.toString(this.k) + ", " + _dafny.toString(this.v) + ")";
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
      return FastP.KU.create_KU(_dafny.Seq.of(), FastP.JU.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return KU.Default();
        }
      };
    }
  }

  $module.St = class St {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Done() {
      let $dt = new St(0);
      return $dt;
    }
    static create_Bad() {
      let $dt = new St(1);
      return $dt;
    }
    static create_Exh() {
      let $dt = new St(2);
      return $dt;
    }
    get is_Done() { return this.$tag === 0; }
    get is_Bad() { return this.$tag === 1; }
    get is_Exh() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield St.create_Done();
      yield St.create_Bad();
      yield St.create_Exh();
    }
    toString() {
      if (this.$tag === 0) {
        return "FastP.St.Done";
      } else if (this.$tag === 1) {
        return "FastP.St.Bad";
      } else if (this.$tag === 2) {
        return "FastP.St.Exh";
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
      } else if (this.$tag === 2) {
        return other.$tag === 2;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return FastP.St.create_Done();
    }
    static Rtd() {
      return class {
        static get Default() {
          return St.Default();
        }
      };
    }
  }

  $module.CP = class CP {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_CP(a, c) {
      let $dt = new CP(0);
      $dt.a = a;
      $dt.c = c;
      return $dt;
    }
    get is_CP() { return this.$tag === 0; }
    get dtor_a() { return this.a; }
    get dtor_c() { return this.c; }
    toString() {
      if (this.$tag === 0) {
        return "FastP.CP.CP" + "(" + _dafny.toString(this.a) + ", " + _dafny.toString(this.c) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.a === other.a && this.c === other.c;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return FastP.CP.create_CP(null, 0);
    }
    static Rtd() {
      return class {
        static get Default() {
          return CP.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module FastP
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
    static ParseAcceptsU(t, seed) {
      return Fast.__default.AcceptsU(t, seed);
    };
    static CanonicalOfValueU(u) {
      let st = FastP.St.Default();
      let b = [];
      let n = 0;
      let _out0;
      let _out1;
      let _out2;
      let _outcollector0 = FastP.__default.CanonU(u);
      _out0 = _outcollector0[0];
      _out1 = _outcollector0[1];
      _out2 = _outcollector0[2];
      st = _out0;
      b = _out1;
      n = _out2;
      return [st, b, n];
    }
  };
  return $module;
})(); // end of module Api
let _module = (function() {
  let $module = {};

  return $module;
})(); // end of module _module

// ---- exports (appended by formal/dafny/build-ext.sh) ----
module.exports = { _dafny, Utf, B64, Json, Fast, FastP, Api };
