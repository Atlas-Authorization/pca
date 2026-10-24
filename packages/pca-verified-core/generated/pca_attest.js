// Dafny program Attest.dfy compiled into JavaScript
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
let Attest = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Attest._default";
    }
    _parentTraits() {
      return [];
    }
    static Field(m, f) {
      if ((f).isEqualTo(_dafny.ZERO)) {
        return (m).dtor_f0;
      } else if ((f).isEqualTo(_dafny.ONE)) {
        return (m).dtor_f1;
      } else if ((f).isEqualTo(new BigNumber(2))) {
        return (m).dtor_f2;
      } else if ((f).isEqualTo(new BigNumber(3))) {
        return (m).dtor_f3;
      } else if ((f).isEqualTo(new BigNumber(4))) {
        return (m).dtor_f4;
      } else {
        return (m).dtor_f5;
      }
    };
    static Passes(r) {
      return ((((r).is_Res) && ((r).dtor_ok)) && ((r).dtor_bound)) && ((r).dtor_hasMeasured);
    };
    static Failed(r) {
      return (!((r).is_Malformed)) && (!(Attest.__default.Passes(r)));
    };
    static Step(st, i, req, r) {
      let _source0 = st;
      {
        if (_source0.is_Done) {
          return st;
        }
      }
      {
        let _0_p = (_source0).passed;
        if ((r).is_Malformed) {
          return Attest.St.create_Done(Attest.MFail.create_ErrorCaught());
        } else if (Attest.__default.Passes(r)) {
          return Attest.St.create_Running(_dafny.Seq.Concat(_0_p, _dafny.Seq.of(_dafny.Tuple.of(i, (r).dtor_m))));
        } else if (req) {
          return Attest.St.create_Done(Attest.MFail.create_RequiredFailed(i));
        } else {
          return st;
        }
      }
    };
    static Fold(reqs, rs, st, k) {
      TAIL_CALL_START: while (true) {
        if ((k).isEqualTo(new BigNumber((rs).length))) {
          return st;
        } else {
          let _in0 = reqs;
          let _in1 = rs;
          let _in2 = Attest.__default.Step(st, k, (reqs)[k], (rs)[k]);
          let _in3 = (k).plus(_dafny.ONE);
          reqs = _in0;
          rs = _in1;
          st = _in2;
          k = _in3;
          continue TAIL_CALL_START;
        }
      }
    };
    static PickRec(p, f, chosen, wh) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((p).length)).isEqualTo(_dafny.ZERO)) {
          return Attest.PickRes.create_Picked(chosen);
        } else {
          let _0_v = Attest.__default.Field(((p)[_dafny.ZERO])[1], f);
          if ((_0_v).isEqualTo(_dafny.ZERO)) {
            let _in0 = (p).slice(_dafny.ONE);
            let _in1 = f;
            let _in2 = chosen;
            let _in3 = wh;
            p = _in0;
            f = _in1;
            chosen = _in2;
            wh = _in3;
            continue TAIL_CALL_START;
          } else if ((chosen).isEqualTo(_dafny.ZERO)) {
            let _in4 = (p).slice(_dafny.ONE);
            let _in5 = f;
            let _in6 = _0_v;
            let _in7 = ((p)[_dafny.ZERO])[0];
            p = _in4;
            f = _in5;
            chosen = _in6;
            wh = _in7;
            continue TAIL_CALL_START;
          } else if (!(chosen).isEqualTo(_0_v)) {
            return Attest.PickRes.create_Conflicted(wh, ((p)[_dafny.ZERO])[0]);
          } else {
            let _in8 = (p).slice(_dafny.ONE);
            let _in9 = f;
            let _in10 = chosen;
            let _in11 = wh;
            p = _in8;
            f = _in9;
            chosen = _in10;
            wh = _in11;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static Compat(p, f, chosen) {
      return (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((p).length)), true, function (_forall_var_0) {
        let _0_a = _forall_var_0;
        return !(((((_dafny.ZERO).isLessThanOrEqualTo(_0_a)) && ((_0_a).isLessThan(new BigNumber((p).length)))) && (!(Attest.__default.Field(((p)[_0_a])[1], f)).isEqualTo(_dafny.ZERO))) && (!(chosen).isEqualTo(_dafny.ZERO))) || ((Attest.__default.Field(((p)[_0_a])[1], f)).isEqualTo(chosen));
      })) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((p).length)), true, function (_forall_var_1) {
        let _1_a = _forall_var_1;
        return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((p).length)), true, function (_forall_var_2) {
          let _2_b = _forall_var_2;
          return !((((((_dafny.ZERO).isLessThanOrEqualTo(_1_a)) && ((_1_a).isLessThan(new BigNumber((p).length)))) && (((_dafny.ZERO).isLessThanOrEqualTo(_2_b)) && ((_2_b).isLessThan(new BigNumber((p).length))))) && (!(Attest.__default.Field(((p)[_1_a])[1], f)).isEqualTo(_dafny.ZERO))) && (!(Attest.__default.Field(((p)[_2_b])[1], f)).isEqualTo(_dafny.ZERO))) || ((Attest.__default.Field(((p)[_1_a])[1], f)).isEqualTo(Attest.__default.Field(((p)[_2_b])[1], f)));
        });
      }));
    };
    static ConflictFree(p) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, (new BigNumber(5)).plus(_dafny.ONE)), true, function (_forall_var_0) {
        let _0_f = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_f)) && ((_0_f).isLessThanOrEqualTo(new BigNumber(5)))) || (Attest.__default.Compat(p, _0_f, _dafny.ZERO));
      });
    };
    static AllZero(p, f) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((p).length)), true, function (_forall_var_0) {
        let _0_a = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_a)) && ((_0_a).isLessThan(new BigNumber((p).length)))) || ((Attest.__default.Field(((p)[_0_a])[1], f)).isEqualTo(_dafny.ZERO));
      });
    };
    static Reconcile(p) {
      let _0_r0 = Attest.__default.PickRec(p, _dafny.ZERO, _dafny.ZERO, new BigNumber(-1));
      if ((_0_r0).is_Conflicted) {
        return Attest.Recon.create_Clash(_dafny.ZERO, (_0_r0).dtor_who, (_0_r0).dtor_at2);
      } else {
        let _1_r1 = Attest.__default.PickRec(p, _dafny.ONE, _dafny.ZERO, new BigNumber(-1));
        if ((_1_r1).is_Conflicted) {
          return Attest.Recon.create_Clash(_dafny.ONE, (_1_r1).dtor_who, (_1_r1).dtor_at2);
        } else {
          let _2_r2 = Attest.__default.PickRec(p, new BigNumber(2), _dafny.ZERO, new BigNumber(-1));
          if ((_2_r2).is_Conflicted) {
            return Attest.Recon.create_Clash(new BigNumber(2), (_2_r2).dtor_who, (_2_r2).dtor_at2);
          } else {
            let _3_r3 = Attest.__default.PickRec(p, new BigNumber(3), _dafny.ZERO, new BigNumber(-1));
            if ((_3_r3).is_Conflicted) {
              return Attest.Recon.create_Clash(new BigNumber(3), (_3_r3).dtor_who, (_3_r3).dtor_at2);
            } else {
              let _4_r4 = Attest.__default.PickRec(p, new BigNumber(4), _dafny.ZERO, new BigNumber(-1));
              if ((_4_r4).is_Conflicted) {
                return Attest.Recon.create_Clash(new BigNumber(4), (_4_r4).dtor_who, (_4_r4).dtor_at2);
              } else {
                let _5_r5 = Attest.__default.PickRec(p, new BigNumber(5), _dafny.ZERO, new BigNumber(-1));
                if ((_5_r5).is_Conflicted) {
                  return Attest.Recon.create_Clash(new BigNumber(5), (_5_r5).dtor_who, (_5_r5).dtor_at2);
                } else {
                  return Attest.Recon.create_Merged(Attest.Ident.create_Ident((_0_r0).dtor_v, (_1_r1).dtor_v, (_2_r2).dtor_v, (_3_r3).dtor_v, (_4_r4).dtor_v, (_5_r5).dtor_v, Attest.__default.WeightsMeasuredOf(p, (_1_r1).dtor_v)));
                }
              }
            }
          }
        }
      }
    };
    static WeightsMeasuredOf(p, w) {
      return (!(w).isEqualTo(_dafny.ZERO)) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((p).length)), false, function (_exists_var_0) {
        let _0_a = _exists_var_0;
        return ((((_dafny.ZERO).isLessThanOrEqualTo(_0_a)) && ((_0_a).isLessThan(new BigNumber((p).length)))) && ((((p)[_0_a])[1]).dtor_weightsMeasured)) && (((((p)[_0_a])[1]).dtor_f1).isEqualTo(w));
      }));
    };
    static Collect(rs, k) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((k).isEqualTo(new BigNumber((rs).length))) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, ((Attest.__default.Passes((rs)[k])) ? (_dafny.Seq.of(_dafny.Tuple.of(k, ((rs)[k]).dtor_m))) : (_dafny.Seq.of())));
          let _in0 = rs;
          let _in1 = (k).plus(_dafny.ONE);
          rs = _in0;
          k = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static FirstBad(reqs, rs, k) {
      TAIL_CALL_START: while (true) {
        if ((k).isEqualTo(new BigNumber((rs).length))) {
          return Attest.Option.create_None();
        } else if (((rs)[k]).is_Malformed) {
          return Attest.Option.create_Some(Attest.MFail.create_ErrorCaught());
        } else if (((reqs)[k]) && (!(Attest.__default.Passes((rs)[k])))) {
          return Attest.Option.create_Some(Attest.MFail.create_RequiredFailed(k));
        } else {
          let _in0 = reqs;
          let _in1 = rs;
          let _in2 = (k).plus(_dafny.ONE);
          reqs = _in0;
          rs = _in1;
          k = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static Idxs(p) {
      return _dafny.Seq.Create(new BigNumber((p).length), ((_0_p) => function (_1_i) {
        return ((_0_p)[_1_i])[0];
      })(p));
    };
    static Finish(thr, st) {
      let _source0 = st;
      {
        if (_source0.is_Done) {
          let _0_f = (_source0).f;
          return Attest.MOut.create_MFail(_0_f);
        }
      }
      {
        let _1_p = (_source0).passed;
        if ((new BigNumber((_1_p).length)).isLessThan(thr)) {
          return Attest.MOut.create_MFail(Attest.MFail.create_BelowThreshold(new BigNumber((_1_p).length)));
        } else {
          let _source1 = Attest.__default.Reconcile(_1_p);
          {
            if (_source1.is_Clash) {
              let _2_f = (_source1).field;
              let _3_a = (_source1).first;
              let _4_b = (_source1).second;
              return Attest.MOut.create_MFail(Attest.MFail.create_Conflict(_2_f, _3_a, _4_b));
            }
          }
          {
            let _5_m = (_source1).m;
            return Attest.MOut.create_MOk(_5_m, Attest.__default.Idxs(_1_p));
          }
        }
      }
    };
    static Run(reqs, rs, thr) {
      return Attest.__default.Finish(thr, Attest.__default.Fold(reqs, rs, Attest.St.create_Running(_dafny.Seq.of()), _dafny.ZERO));
    };
    static NoBad(reqs, rs) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((rs).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((rs).length)))) || ((!(((rs)[_0_i]).is_Malformed)) && (!((reqs)[_0_i]) || (Attest.__default.Passes((rs)[_0_i]))));
      });
    };
    static OkSpec(reqs, rs, thr) {
      return ((Attest.__default.NoBad(reqs, rs)) && ((thr).isLessThanOrEqualTo(new BigNumber((Attest.__default.Collect(rs, _dafny.ZERO)).length)))) && (Attest.__default.ConflictFree(Attest.__default.Collect(rs, _dafny.ZERO)));
    };
    static ValidPolicy(ids, thr) {
      return ((((_dafny.ONE).isLessThanOrEqualTo(new BigNumber((ids).length))) && (((_dafny.ONE).isLessThanOrEqualTo(thr)) && ((thr).isLessThanOrEqualTo(new BigNumber((ids).length))))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((ids).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((ids).length)))) || (!((ids)[_0_i]).isEqualTo(_dafny.ZERO));
      }))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((ids).length)), true, function (_forall_var_1) {
        let _1_i = _forall_var_1;
        return _dafny.Quantifier(_dafny.IntegerRange((_1_i).plus(_dafny.ONE), new BigNumber((ids).length)), true, function (_forall_var_2) {
          let _2_j = _forall_var_2;
          return !((((_dafny.ZERO).isLessThanOrEqualTo(_1_i)) && ((_1_i).isLessThan(_2_j))) && ((_2_j).isLessThan(new BigNumber((ids).length)))) || (!((ids)[_1_i]).isEqualTo((ids)[_2_j]));
        });
      }));
    };
    static Incl(s, x) {
      return _dafny.Seq.contains(s, x);
    };
    static MatchBinding(id, b) {
      if (((_dafny.ZERO).isLessThan(new BigNumber(((b).dtor_modelAllow).length))) && (!(Attest.__default.Incl((b).dtor_modelAllow, (id).dtor_model)))) {
        return Attest.Option.create_Some(Attest.BFail.create_BModel());
      } else if (((b).dtor_minM).is_MinBad) {
        return Attest.Option.create_Some(Attest.BFail.create_BMinBad());
      } else if ((((b).dtor_minM).is_EqPin) && (!(((b).dtor_minM).dtor_matches))) {
        return Attest.Option.create_Some(Attest.BFail.create_BMinEq());
      } else if ((((b).dtor_minM).is_Svn) && ((((b).dtor_minM).dtor_parse).is_SvnNotInteger)) {
        return Attest.Option.create_Some(Attest.BFail.create_BMinSvnNotInt());
      } else if ((((b).dtor_minM).is_Svn) && ((((b).dtor_minM).dtor_parse).is_SvnBelow)) {
        return Attest.Option.create_Some(Attest.BFail.create_BMinSvnBelow());
      } else if (((b).dtor_operatorPinned) && (!((id).dtor_operatorMatches))) {
        return Attest.Option.create_Some(Attest.BFail.create_BOperator());
      } else if (((b).dtor_requireMeasured) && (!((id).dtor_weightsMeasured))) {
        return Attest.Option.create_Some(Attest.BFail.create_BNotMeasured());
      } else if (((_dafny.ZERO).isLessThan(new BigNumber(((b).dtor_weightsAllow).length))) && (!(Attest.__default.Incl((b).dtor_weightsAllow, (id).dtor_weights)))) {
        return Attest.Option.create_Some(Attest.BFail.create_BWeights());
      } else if (((_dafny.ZERO).isLessThan(new BigNumber(((b).dtor_sysAllow).length))) && ((!((id).dtor_hasSys)) || (!(Attest.__default.Incl((b).dtor_sysAllow, (id).dtor_sys))))) {
        return Attest.Option.create_Some(Attest.BFail.create_BSys());
      } else if (((_dafny.ZERO).isLessThan(new BigNumber(((b).dtor_toolAllow).length))) && ((!((id).dtor_hasTool)) || (!(Attest.__default.Incl((b).dtor_toolAllow, (id).dtor_tool))))) {
        return Attest.Option.create_Some(Attest.BFail.create_BTool());
      } else {
        return Attest.Option.create_None();
      }
    };
    static BindingHolds(id, b) {
      return ((((((((!((_dafny.ZERO).isLessThan(new BigNumber(((b).dtor_modelAllow).length))) || (_dafny.Seq.contains((b).dtor_modelAllow, (id).dtor_model))) && (!(((b).dtor_minM).is_MinBad))) && (!(((b).dtor_minM).is_EqPin) || (((b).dtor_minM).dtor_matches))) && (!(((b).dtor_minM).is_Svn) || ((((b).dtor_minM).dtor_parse).is_SvnOk))) && (!((b).dtor_operatorPinned) || ((id).dtor_operatorMatches))) && (!((b).dtor_requireMeasured) || ((id).dtor_weightsMeasured))) && (!((_dafny.ZERO).isLessThan(new BigNumber(((b).dtor_weightsAllow).length))) || (_dafny.Seq.contains((b).dtor_weightsAllow, (id).dtor_weights)))) && (!((_dafny.ZERO).isLessThan(new BigNumber(((b).dtor_sysAllow).length))) || (((id).dtor_hasSys) && (_dafny.Seq.contains((b).dtor_sysAllow, (id).dtor_sys))))) && (!((_dafny.ZERO).isLessThan(new BigNumber(((b).dtor_toolAllow).length))) || (((id).dtor_hasTool) && (_dafny.Seq.contains((b).dtor_toolAllow, (id).dtor_tool))));
    };
    static NoBinding() {
      return Attest.Binding.create_Binding(_dafny.Seq.of(), Attest.MinM.create_NoMin(), false, false, _dafny.Seq.of(), _dafny.Seq.of(), _dafny.Seq.of());
    };
    static AllowNarrower(a, b) {
      return ((new BigNumber((b).length)).isEqualTo(_dafny.ZERO)) || (((_dafny.ZERO).isLessThan(new BigNumber((a).length))) && (_dafny.Quantifier((a).UniqueElements, true, function (_forall_var_0) {
        let _0_x = _forall_var_0;
        return !(_dafny.Seq.contains(a, _0_x)) || (_dafny.Seq.contains(b, _0_x));
      })));
    };
    static RequiresAttestation(f) {
      return ((((((((f).dtor_modelAllowNonEmpty) || ((f).dtor_hasMin)) || ((f).dtor_operatorNonEmpty)) || ((f).dtor_weightsNonEmpty)) || ((f).dtor_sysNonEmpty)) || ((f).dtor_toolNonEmpty)) || ((f).dtor_requireHw)) || ((f).dtor_requireMeasured);
    };
    static Order(hasHw) {
      return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(Attest.Kind.create_KPresent(), Attest.Kind.create_KBindingConstructible(), Attest.Kind.create_KGrantRef(), Attest.Kind.create_KEpoch(), Attest.Kind.create_KQuote(), Attest.Kind.create_KDocNonce(), Attest.Kind.create_KReqHwVerifier(), Attest.Kind.create_KReqHwMode()), ((hasHw) ? (_dafny.Seq.of(Attest.Kind.create_KHwNonceAge(), Attest.Kind.create_KHwOk(), Attest.Kind.create_KHwBound(), Attest.Kind.create_KHwMeasured())) : (_dafny.Seq.of(Attest.Kind.create_KSoftMode(), Attest.Kind.create_KAttestorTrusted(), Attest.Kind.create_KAlgKnown(), Attest.Kind.create_KSigOk(), Attest.Kind.create_KBindingPresent(), Attest.Kind.create_KBindingEq(), Attest.Kind.create_KWindowWellFormed(), Attest.Kind.create_KNotYetValid(), Attest.Kind.create_KExpired(), Attest.Kind.create_KSoftNonceAge())))), _dafny.Seq.of(Attest.Kind.create_KAgentBinding()));
    };
    static Holds(f, k) {
      let _source0 = k;
      {
        if (_source0.is_KPresent) {
          return (f).dtor_present;
        }
      }
      {
        if (_source0.is_KBindingConstructible) {
          return (f).dtor_bindingConstructible;
        }
      }
      {
        if (_source0.is_KGrantRef) {
          return (f).dtor_grantRefOk;
        }
      }
      {
        if (_source0.is_KEpoch) {
          return (f).dtor_epochOk;
        }
      }
      {
        if (_source0.is_KQuote) {
          return (f).dtor_quoteOk;
        }
      }
      {
        if (_source0.is_KDocNonce) {
          return (f).dtor_docNonceOk;
        }
      }
      {
        if (_source0.is_KReqHwVerifier) {
          return (!((f).dtor_requireHw)) || ((f).dtor_hasHwVerifier);
        }
      }
      {
        if (_source0.is_KReqHwMode) {
          return (!((f).dtor_requireHw)) || ((f).dtor_docIsHardware);
        }
      }
      {
        if (_source0.is_KHwNonceAge) {
          return (f).dtor_hwNonceAgeOk;
        }
      }
      {
        if (_source0.is_KHwOk) {
          return (f).dtor_hwOk;
        }
      }
      {
        if (_source0.is_KHwBound) {
          return (f).dtor_hwBound;
        }
      }
      {
        if (_source0.is_KHwMeasured) {
          return (f).dtor_hwHasMeasured;
        }
      }
      {
        if (_source0.is_KSoftMode) {
          return (f).dtor_docIsSoftware;
        }
      }
      {
        if (_source0.is_KAttestorTrusted) {
          return (f).dtor_attestorTrusted;
        }
      }
      {
        if (_source0.is_KAlgKnown) {
          return (f).dtor_algKnown;
        }
      }
      {
        if (_source0.is_KSigOk) {
          return (f).dtor_sigOk;
        }
      }
      {
        if (_source0.is_KBindingPresent) {
          return (f).dtor_bindingPresent;
        }
      }
      {
        if (_source0.is_KBindingEq) {
          return (f).dtor_bindingEq;
        }
      }
      {
        if (_source0.is_KWindowWellFormed) {
          return (f).dtor_windowWellFormed;
        }
      }
      {
        if (_source0.is_KNotYetValid) {
          return !((f).dtor_notYetValid);
        }
      }
      {
        if (_source0.is_KExpired) {
          return !((f).dtor_expired);
        }
      }
      {
        if (_source0.is_KSoftNonceAge) {
          return (!((f).dtor_hasNonceIssuedAt)) || ((f).dtor_softNonceAgeOk);
        }
      }
      {
        return (f).dtor_agentBindingOk;
      }
    };
    static GateStep(acc, k, holds) {
      if ((acc).is_Some) {
        return acc;
      } else if (holds) {
        return Attest.Option.create_None();
      } else {
        return Attest.Option.create_Some(k);
      }
    };
    static GateFrom(f, ks, acc) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((ks).length)).isEqualTo(_dafny.ZERO)) {
          return acc;
        } else {
          let _in0 = f;
          let _in1 = (ks).slice(_dafny.ONE);
          let _in2 = Attest.__default.GateStep(acc, (ks)[_dafny.ZERO], Attest.__default.Holds(f, (ks)[_dafny.ZERO]));
          f = _in0;
          ks = _in1;
          acc = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static Verify(f) {
      return Attest.__default.GateFrom(f, Attest.__default.Order((f).dtor_hasHwVerifier), Attest.Option.create_None());
    };
    static EffMaxAge(has, v) {
      let _0_m = (((has) && ((_dafny.ZERO).isLessThan(v))) ? (v) : (Attest.__default.MaxAttestationAgeMs));
      if ((_0_m).isLessThan(Attest.__default.MaxAttestationAgeMs)) {
        return _0_m;
      } else {
        return Attest.__default.MaxAttestationAgeMs;
      }
    };
    static NonceAge(hasIssued, issued, now, skew, maxAge) {
      if (!(hasIssued)) {
        return Attest.AgeRes.create_AgeUnknown();
      } else if (((now).plus(skew)).isLessThan(issued)) {
        return Attest.AgeRes.create_AgeFuture();
      } else if (((maxAge).plus(skew)).isLessThan((now).minus(issued))) {
        return Attest.AgeRes.create_AgeStale();
      } else {
        return Attest.AgeRes.create_AgeFresh();
      }
    };
    static Window(now, skew, iat, exp) {
      if ((exp).isLessThan(iat)) {
        return Attest.WinRes.create_WinMalformed();
      } else if (((now).plus(skew)).isLessThan(iat)) {
        return Attest.WinRes.create_WinNotYet();
      } else if ((exp).isLessThan((now).minus(skew))) {
        return Attest.WinRes.create_WinExpired();
      } else {
        return Attest.WinRes.create_WinValid();
      }
    };
    static NeedsConsume(vOk, vBound, hasStore) {
      return ((vOk) && (vBound)) && (hasStore);
    };
    static HookFinal(vOk, vBound, hasStore, consumed) {
      if (Attest.__default.NeedsConsume(vOk, vBound, hasStore)) {
        if (consumed) {
          return Attest.HookOut.create_HookOk();
        } else {
          return Attest.HookOut.create_HookReplay();
        }
      } else if (vOk) {
        return Attest.HookOut.create_HookOk();
      } else {
        return Attest.HookOut.create_HookVerdictFail();
      }
    };
    static IndexOf(xs, n) {
      let _hresult = _dafny.ZERO;
      let _0_j;
      _0_j = _dafny.ZERO;
      while (((_0_j).isLessThan(new BigNumber((xs).length))) && (!(((xs)[_0_j])[0]).isEqualTo(n))) {
        _0_j = (_0_j).plus(_dafny.ONE);
      }
      if ((_0_j).isLessThan(new BigNumber((xs).length))) {
        _hresult = _0_j;
      } else {
        _hresult = new BigNumber(-1);
      }
      return _hresult;
      return _hresult;
    }
    static RemoveAt(xs, i) {
      return _dafny.Seq.Concat((xs).slice(0, i), (xs).slice((i).plus(_dafny.ONE)));
    };
    static Live(e, t, ret) {
      return ((t).minus((e)[1])).isLessThan(ret);
    };
    static DropAged(xs, t, ret) {
      let _hresult = _dafny.Seq.of();
      let _0_k;
      _0_k = _dafny.ZERO;
      while (((_0_k).isLessThan(new BigNumber((xs).length))) && (!(Attest.__default.Live((xs)[_0_k], t, ret)))) {
        _0_k = (_0_k).plus(_dafny.ONE);
      }
      _hresult = (xs).slice(_0_k);
      return _hresult;
      return _hresult;
    }
    static MsConsume(s, n, t) {
      let _0_i = Attest.__default.IndexOf((s).dtor_items, n);
      if (((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && (Attest.__default.Live(((s).dtor_items)[_0_i], t, (s).dtor_ret))) {
        return _dafny.Tuple.of(s, false);
      } else {
        let _1_it = (((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) ? (Attest.__default.RemoveAt((s).dtor_items, _0_i)) : ((s).dtor_items));
        let _2_it2 = ((((s).dtor_max).isLessThanOrEqualTo(new BigNumber((_1_it).length))) ? (Attest.__default.DropAged(_1_it, t, (s).dtor_ret)) : (_1_it));
        if (((s).dtor_max).isLessThanOrEqualTo(new BigNumber((_2_it2).length))) {
          return _dafny.Tuple.of(Attest.MS.create_MS(_2_it2, (s).dtor_max, (s).dtor_ret), false);
        } else {
          return _dafny.Tuple.of(Attest.MS.create_MS(_dafny.Seq.Concat(_2_it2, _dafny.Seq.of(_dafny.Tuple.of(n, t))), (s).dtor_max, (s).dtor_ret), true);
        }
      }
    };
    static ValidStore(max, ret) {
      return ((_dafny.ONE).isLessThanOrEqualTo(max)) && ((_dafny.ONE).isLessThanOrEqualTo(ret));
    };
    static MsEmpty(max, ret) {
      return Attest.MS.create_MS(_dafny.Seq.of(), max, ret);
    };
    static Distinct(xs) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((xs).length)), true, function (_forall_var_0) {
        let _0_a = _forall_var_0;
        return _dafny.Quantifier(_dafny.IntegerRange((_0_a).plus(_dafny.ONE), new BigNumber((xs).length)), true, function (_forall_var_1) {
          let _1_b = _forall_var_1;
          return !((((_dafny.ZERO).isLessThanOrEqualTo(_0_a)) && ((_0_a).isLessThan(_1_b))) && ((_1_b).isLessThan(new BigNumber((xs).length)))) || (!(((xs)[_0_a])[0]).isEqualTo(((xs)[_1_b])[0]));
        });
      });
    };
    static Wf(s) {
      return ((Attest.__default.ValidStore((s).dtor_max, (s).dtor_ret)) && ((new BigNumber(((s).dtor_items).length)).isLessThanOrEqualTo((s).dtor_max))) && (Attest.__default.Distinct((s).dtor_items));
    };
    static DropCount(xs, t, ret) {
      let _0___accumulator = _dafny.ZERO;
      TAIL_CALL_START: while (true) {
        if (((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) || (Attest.__default.Live((xs)[_dafny.ZERO], t, ret))) {
          return (_dafny.ZERO).plus(_0___accumulator);
        } else {
          _0___accumulator = (_0___accumulator).plus(_dafny.ONE);
          let _in0 = (xs).slice(_dafny.ONE);
          let _in1 = t;
          let _in2 = ret;
          xs = _in0;
          t = _in1;
          ret = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static MsApply(s, ops) {
      if ((new BigNumber((ops).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Tuple.of(s, _dafny.ZERO);
      } else {
        let _0_r = Attest.__default.MsConsume(s, ((ops)[_dafny.ZERO])[0], ((ops)[_dafny.ZERO])[1]);
        let _1_rest = Attest.__default.MsApply((_0_r)[0], (ops).slice(_dafny.ONE));
        return _dafny.Tuple.of((_1_rest)[0], ((_1_rest)[1]).plus((((_0_r)[1]) ? (_dafny.ONE) : (_dafny.ZERO))));
      }
    };
    static AHolds(f, k) {
      let _source0 = k;
      {
        if (_source0.is_ASshape) {
          return (f).dtor_shapeOk;
        }
      }
      {
        if (_source0.is_AUnknownIssuer) {
          return (f).dtor_issuerKnown;
        }
      }
      {
        if (_source0.is_AAlgMismatch) {
          return (f).dtor_algMatches;
        }
      }
      {
        if (_source0.is_AIssuerExpired) {
          return (f).dtor_issuerLive;
        }
      }
      {
        if (_source0.is_ABadSig) {
          return (f).dtor_sigOk;
        }
      }
      {
        if (_source0.is_AOptions) {
          return (f).dtor_optionsOk;
        }
      }
      {
        if (_source0.is_ANotYet) {
          return !((((f).dtor_now).plus((f).dtor_skew)).isLessThan((f).dtor_notBefore));
        }
      }
      {
        if (_source0.is_AExpired) {
          return !(((f).dtor_expiresAt).isLessThan(((f).dtor_now).minus((f).dtor_skew)));
        }
      }
      {
        if (_source0.is_ALifetime) {
          return !(((f).dtor_hasMaxLife) && (((f).dtor_maxLife).isLessThan(((f).dtor_expiresAt).minus((f).dtor_notBefore))));
        }
      }
      {
        if (_source0.is_ABelowMin) {
          return !(((f).dtor_hasMin) && (((f).dtor_version).isLessThan((f).dtor_minV)));
        }
      }
      {
        if (_source0.is_ARollback) {
          return !(((f).dtor_hasLast) && (((f).dtor_version).isLessThan((f).dtor_lastV)));
        }
      }
      {
        return !(((((f).dtor_hasLast) && (((f).dtor_version).isEqualTo((f).dtor_lastV))) && ((f).dtor_hasLastDigest)) && (!((f).dtor_lastDigest).isEqualTo((f).dtor_digest)));
      }
    };
    static AGateFrom(f, ks, acc) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((ks).length)).isEqualTo(_dafny.ZERO)) {
          return acc;
        } else {
          let _in0 = f;
          let _in1 = (ks).slice(_dafny.ONE);
          let _in2 = (((acc).is_Some) ? (acc) : (((Attest.__default.AHolds(f, (ks)[_dafny.ZERO])) ? (Attest.Option.create_None()) : (Attest.Option.create_Some((ks)[_dafny.ZERO])))));
          f = _in0;
          ks = _in1;
          acc = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static AllowVerify(f) {
      return Attest.__default.AGateFrom(f, Attest.__default.AOrder, Attest.Option.create_None());
    };
    static KvVersion(k) {
      if ((k).is_KVal) {
        return (k).dtor_v;
      } else {
        return _dafny.ZERO;
      }
    };
    static UpdateFn(cur, v, d) {
      if ((cur).is_KCorrupt) {
        return cur;
      } else if (((cur).is_KVal) && ((v).isLessThanOrEqualTo((cur).dtor_v))) {
        return cur;
      } else {
        return Attest.KV.create_KVal(v, d);
      }
    };
    static DurableStep(read, now, verifyOk, v, d) {
      if ((read).is_KCorrupt) {
        return _dafny.Tuple.of(Attest.DOut.create_DMalformed(), now);
      } else if (!(verifyOk)) {
        return _dafny.Tuple.of(Attest.DOut.create_DVerifyFail(), now);
      } else {
        let _0_after = Attest.__default.UpdateFn(now, v, d);
        if (!((_0_after).is_KVal)) {
          return _dafny.Tuple.of(Attest.DOut.create_DRollback(), _0_after);
        } else if ((v).isLessThan((_0_after).dtor_v)) {
          return _dafny.Tuple.of(Attest.DOut.create_DRollback(), _0_after);
        } else if ((((_0_after).dtor_v).isEqualTo(v)) && (!((_0_after).dtor_d).isEqualTo(d))) {
          return _dafny.Tuple.of(Attest.DOut.create_DConflict(), _0_after);
        } else {
          return _dafny.Tuple.of(Attest.DOut.create_DAccept(), _0_after);
        }
      }
    };
    static DRun(st, ops) {
      if ((new BigNumber((ops).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Tuple.of(st, _dafny.Seq.of());
      } else {
        let _0_r = Attest.__default.DurableStep(((ops)[_dafny.ZERO]).dtor_read, st, ((ops)[_dafny.ZERO]).dtor_verifyOk, ((ops)[_dafny.ZERO]).dtor_v, ((ops)[_dafny.ZERO]).dtor_d);
        let _1_rest = Attest.__default.DRun((_0_r)[1], (ops).slice(_dafny.ONE));
        return _dafny.Tuple.of((_1_rest)[0], _dafny.Seq.Concat(((_dafny.areEqual((_0_r)[0], Attest.DOut.create_DAccept())) ? (_dafny.Seq.of(_dafny.Tuple.of(((ops)[_dafny.ZERO]).dtor_v, ((ops)[_dafny.ZERO]).dtor_d))) : (_dafny.Seq.of())), (_1_rest)[1]));
      }
    };
    static FeedConflict(es, issuer) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((es).length)), false, function (_exists_var_0) {
        let _0_a = _exists_var_0;
        return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((es).length)), false, function (_exists_var_1) {
          let _1_b = _exists_var_1;
          return (((((((_dafny.ZERO).isLessThanOrEqualTo(_0_a)) && ((_0_a).isLessThan(new BigNumber((es).length)))) && (((_dafny.ZERO).isLessThanOrEqualTo(_1_b)) && ((_1_b).isLessThan(new BigNumber((es).length))))) && ((((es)[_0_a]).dtor_issuer).isEqualTo(issuer))) && ((((es)[_1_b]).dtor_issuer).isEqualTo(issuer))) && ((((es)[_0_a]).dtor_version).isEqualTo(((es)[_1_b]).dtor_version))) && (!(((es)[_0_a]).dtor_digest).isEqualTo(((es)[_1_b]).dtor_digest));
        });
      });
    };
    static Highest(es, issuer) {
      if ((new BigNumber((es).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.ZERO;
      } else {
        let _0_h = Attest.__default.Highest((es).slice(_dafny.ONE), issuer);
        if (((((es)[_dafny.ZERO]).dtor_issuer).isEqualTo(issuer)) && ((_0_h).isLessThan(((es)[_dafny.ZERO]).dtor_version))) {
          return ((es)[_dafny.ZERO]).dtor_version;
        } else {
          return _0_h;
        }
      }
    };
    static HasEntry(es, e) {
      return _dafny.Seq.contains(es, e);
    };
    static AnchorScan(es, mine) {
      if (Attest.__default.FeedConflict(es, (mine).dtor_issuer)) {
        return Attest.Option.create_Some(Attest.AnchorFail.create_ALogConflict());
      } else if (((mine).dtor_version).isLessThan(Attest.__default.Highest(es, (mine).dtor_issuer))) {
        return Attest.Option.create_Some(Attest.AnchorFail.create_AAnchoredRollback());
      } else if (!(_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((es).length)), false, function (_exists_var_0) {
        let _0_a = _exists_var_0;
        return (((((_dafny.ZERO).isLessThanOrEqualTo(_0_a)) && ((_0_a).isLessThan(new BigNumber((es).length)))) && ((((es)[_0_a]).dtor_issuer).isEqualTo((mine).dtor_issuer))) && ((((es)[_0_a]).dtor_version).isEqualTo((mine).dtor_version))) && ((((es)[_0_a]).dtor_digest).isEqualTo((mine).dtor_digest));
      }))) {
        return Attest.Option.create_Some(Attest.AnchorFail.create_ANotAnchored());
      } else {
        return Attest.Option.create_None();
      }
    };
    static CacheStage(hasCached, headSize, cachedSize, rootsEqual) {
      if (!(hasCached)) {
        return Attest.CacheOut.create_CacheNone();
      } else if ((headSize).isLessThan(cachedSize)) {
        return Attest.CacheOut.create_CacheRollback();
      } else if ((headSize).isEqualTo(cachedSize)) {
        if (rootsEqual) {
          return Attest.CacheOut.create_CacheOk();
        } else {
          return Attest.CacheOut.create_CacheSplitView();
        }
      } else {
        return Attest.CacheOut.create_CacheNeedConsistency();
      }
    };
    static HeadFreshness(optionsOk, ts, now, skew, maxAge) {
      if (!(optionsOk)) {
        return Attest.HeadAge.create_HeadBadOptions();
      } else if (((now).plus((((_dafny.ZERO).isLessThanOrEqualTo(skew)) ? (skew) : (_dafny.ZERO)))).isLessThan(ts)) {
        return Attest.HeadAge.create_HeadFuture();
      } else if ((maxAge).isLessThan((now).minus(ts))) {
        return Attest.HeadAge.create_HeadStale();
      } else {
        return Attest.HeadAge.create_HeadFresh();
      }
    };
    static get MaxAttestationAgeMs() {
      return new BigNumber(300000);
    };
    static get AOrder() {
      return _dafny.Seq.of(Attest.AKind.create_ASshape(), Attest.AKind.create_AUnknownIssuer(), Attest.AKind.create_AAlgMismatch(), Attest.AKind.create_AIssuerExpired(), Attest.AKind.create_ABadSig(), Attest.AKind.create_AOptions(), Attest.AKind.create_ANotYet(), Attest.AKind.create_AExpired(), Attest.AKind.create_ALifetime(), Attest.AKind.create_ABelowMin(), Attest.AKind.create_ARollback(), Attest.AKind.create_AConflict());
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
        return "Attest.Option.None";
      } else if (this.$tag === 1) {
        return "Attest.Option.Some" + "(" + _dafny.toString(this.v) + ")";
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
      return Attest.Option.create_None();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Option.Default();
        }
      };
    }
  }

  $module.Ident = class Ident {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Ident(f0, f1, f2, f3, f4, f5, weightsMeasured) {
      let $dt = new Ident(0);
      $dt.f0 = f0;
      $dt.f1 = f1;
      $dt.f2 = f2;
      $dt.f3 = f3;
      $dt.f4 = f4;
      $dt.f5 = f5;
      $dt.weightsMeasured = weightsMeasured;
      return $dt;
    }
    get is_Ident() { return this.$tag === 0; }
    get dtor_f0() { return this.f0; }
    get dtor_f1() { return this.f1; }
    get dtor_f2() { return this.f2; }
    get dtor_f3() { return this.f3; }
    get dtor_f4() { return this.f4; }
    get dtor_f5() { return this.f5; }
    get dtor_weightsMeasured() { return this.weightsMeasured; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.Ident.Ident" + "(" + _dafny.toString(this.f0) + ", " + _dafny.toString(this.f1) + ", " + _dafny.toString(this.f2) + ", " + _dafny.toString(this.f3) + ", " + _dafny.toString(this.f4) + ", " + _dafny.toString(this.f5) + ", " + _dafny.toString(this.weightsMeasured) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.f0, other.f0) && _dafny.areEqual(this.f1, other.f1) && _dafny.areEqual(this.f2, other.f2) && _dafny.areEqual(this.f3, other.f3) && _dafny.areEqual(this.f4, other.f4) && _dafny.areEqual(this.f5, other.f5) && this.weightsMeasured === other.weightsMeasured;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.Ident.create_Ident(_dafny.ZERO, _dafny.ZERO, _dafny.ZERO, _dafny.ZERO, _dafny.ZERO, _dafny.ZERO, false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Ident.Default();
        }
      };
    }
  }

  $module.RootRes = class RootRes {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Malformed() {
      let $dt = new RootRes(0);
      return $dt;
    }
    static create_NullRes() {
      let $dt = new RootRes(1);
      return $dt;
    }
    static create_Res(ok, bound, hasMeasured, m) {
      let $dt = new RootRes(2);
      $dt.ok = ok;
      $dt.bound = bound;
      $dt.hasMeasured = hasMeasured;
      $dt.m = m;
      return $dt;
    }
    get is_Malformed() { return this.$tag === 0; }
    get is_NullRes() { return this.$tag === 1; }
    get is_Res() { return this.$tag === 2; }
    get dtor_ok() { return this.ok; }
    get dtor_bound() { return this.bound; }
    get dtor_hasMeasured() { return this.hasMeasured; }
    get dtor_m() { return this.m; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.RootRes.Malformed";
      } else if (this.$tag === 1) {
        return "Attest.RootRes.NullRes";
      } else if (this.$tag === 2) {
        return "Attest.RootRes.Res" + "(" + _dafny.toString(this.ok) + ", " + _dafny.toString(this.bound) + ", " + _dafny.toString(this.hasMeasured) + ", " + _dafny.toString(this.m) + ")";
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
        return other.$tag === 2 && this.ok === other.ok && this.bound === other.bound && this.hasMeasured === other.hasMeasured && _dafny.areEqual(this.m, other.m);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.RootRes.create_Malformed();
    }
    static Rtd() {
      return class {
        static get Default() {
          return RootRes.Default();
        }
      };
    }
  }

  $module.MFail = class MFail {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_RequiredFailed(idx) {
      let $dt = new MFail(0);
      $dt.idx = idx;
      return $dt;
    }
    static create_ErrorCaught() {
      let $dt = new MFail(1);
      return $dt;
    }
    static create_BelowThreshold(count) {
      let $dt = new MFail(2);
      $dt.count = count;
      return $dt;
    }
    static create_Conflict(field, first, second) {
      let $dt = new MFail(3);
      $dt.field = field;
      $dt.first = first;
      $dt.second = second;
      return $dt;
    }
    get is_RequiredFailed() { return this.$tag === 0; }
    get is_ErrorCaught() { return this.$tag === 1; }
    get is_BelowThreshold() { return this.$tag === 2; }
    get is_Conflict() { return this.$tag === 3; }
    get dtor_idx() { return this.idx; }
    get dtor_count() { return this.count; }
    get dtor_field() { return this.field; }
    get dtor_first() { return this.first; }
    get dtor_second() { return this.second; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.MFail.RequiredFailed" + "(" + _dafny.toString(this.idx) + ")";
      } else if (this.$tag === 1) {
        return "Attest.MFail.ErrorCaught";
      } else if (this.$tag === 2) {
        return "Attest.MFail.BelowThreshold" + "(" + _dafny.toString(this.count) + ")";
      } else if (this.$tag === 3) {
        return "Attest.MFail.Conflict" + "(" + _dafny.toString(this.field) + ", " + _dafny.toString(this.first) + ", " + _dafny.toString(this.second) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.idx, other.idx);
      } else if (this.$tag === 1) {
        return other.$tag === 1;
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.count, other.count);
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.field, other.field) && _dafny.areEqual(this.first, other.first) && _dafny.areEqual(this.second, other.second);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.MFail.create_RequiredFailed(_dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return MFail.Default();
        }
      };
    }
  }

  $module.MOut = class MOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_MOk(m, idxs) {
      let $dt = new MOut(0);
      $dt.m = m;
      $dt.idxs = idxs;
      return $dt;
    }
    static create_MFail(f) {
      let $dt = new MOut(1);
      $dt.f = f;
      return $dt;
    }
    get is_MOk() { return this.$tag === 0; }
    get is_MFail() { return this.$tag === 1; }
    get dtor_m() { return this.m; }
    get dtor_idxs() { return this.idxs; }
    get dtor_f() { return this.f; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.MOut.MOk" + "(" + _dafny.toString(this.m) + ", " + _dafny.toString(this.idxs) + ")";
      } else if (this.$tag === 1) {
        return "Attest.MOut.MFail" + "(" + _dafny.toString(this.f) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.m, other.m) && _dafny.areEqual(this.idxs, other.idxs);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.f, other.f);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.MOut.create_MOk(Attest.Ident.Default(), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return MOut.Default();
        }
      };
    }
  }

  $module.St = class St {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Running(passed) {
      let $dt = new St(0);
      $dt.passed = passed;
      return $dt;
    }
    static create_Done(f) {
      let $dt = new St(1);
      $dt.f = f;
      return $dt;
    }
    get is_Running() { return this.$tag === 0; }
    get is_Done() { return this.$tag === 1; }
    get dtor_passed() { return this.passed; }
    get dtor_f() { return this.f; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.St.Running" + "(" + _dafny.toString(this.passed) + ")";
      } else if (this.$tag === 1) {
        return "Attest.St.Done" + "(" + _dafny.toString(this.f) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.passed, other.passed);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.f, other.f);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.St.create_Running(_dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return St.Default();
        }
      };
    }
  }

  $module.PickRes = class PickRes {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Picked(v) {
      let $dt = new PickRes(0);
      $dt.v = v;
      return $dt;
    }
    static create_Conflicted(who, at2) {
      let $dt = new PickRes(1);
      $dt.who = who;
      $dt.at2 = at2;
      return $dt;
    }
    get is_Picked() { return this.$tag === 0; }
    get is_Conflicted() { return this.$tag === 1; }
    get dtor_v() { return this.v; }
    get dtor_who() { return this.who; }
    get dtor_at2() { return this.at2; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.PickRes.Picked" + "(" + _dafny.toString(this.v) + ")";
      } else if (this.$tag === 1) {
        return "Attest.PickRes.Conflicted" + "(" + _dafny.toString(this.who) + ", " + _dafny.toString(this.at2) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.v, other.v);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.who, other.who) && _dafny.areEqual(this.at2, other.at2);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.PickRes.create_Picked(_dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return PickRes.Default();
        }
      };
    }
  }

  $module.Recon = class Recon {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Merged(m) {
      let $dt = new Recon(0);
      $dt.m = m;
      return $dt;
    }
    static create_Clash(field, first, second) {
      let $dt = new Recon(1);
      $dt.field = field;
      $dt.first = first;
      $dt.second = second;
      return $dt;
    }
    get is_Merged() { return this.$tag === 0; }
    get is_Clash() { return this.$tag === 1; }
    get dtor_m() { return this.m; }
    get dtor_field() { return this.field; }
    get dtor_first() { return this.first; }
    get dtor_second() { return this.second; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.Recon.Merged" + "(" + _dafny.toString(this.m) + ")";
      } else if (this.$tag === 1) {
        return "Attest.Recon.Clash" + "(" + _dafny.toString(this.field) + ", " + _dafny.toString(this.first) + ", " + _dafny.toString(this.second) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.m, other.m);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.field, other.field) && _dafny.areEqual(this.first, other.first) && _dafny.areEqual(this.second, other.second);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.Recon.create_Merged(Attest.Ident.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Recon.Default();
        }
      };
    }
  }

  $module.SvnCheck = class SvnCheck {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_SvnNotInteger() {
      let $dt = new SvnCheck(0);
      return $dt;
    }
    static create_SvnBelow() {
      let $dt = new SvnCheck(1);
      return $dt;
    }
    static create_SvnOk() {
      let $dt = new SvnCheck(2);
      return $dt;
    }
    get is_SvnNotInteger() { return this.$tag === 0; }
    get is_SvnBelow() { return this.$tag === 1; }
    get is_SvnOk() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield SvnCheck.create_SvnNotInteger();
      yield SvnCheck.create_SvnBelow();
      yield SvnCheck.create_SvnOk();
    }
    toString() {
      if (this.$tag === 0) {
        return "Attest.SvnCheck.SvnNotInteger";
      } else if (this.$tag === 1) {
        return "Attest.SvnCheck.SvnBelow";
      } else if (this.$tag === 2) {
        return "Attest.SvnCheck.SvnOk";
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
      return Attest.SvnCheck.create_SvnNotInteger();
    }
    static Rtd() {
      return class {
        static get Default() {
          return SvnCheck.Default();
        }
      };
    }
  }

  $module.MinM = class MinM {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_NoMin() {
      let $dt = new MinM(0);
      return $dt;
    }
    static create_EqPin(matches) {
      let $dt = new MinM(1);
      $dt.matches = matches;
      return $dt;
    }
    static create_Svn(parse) {
      let $dt = new MinM(2);
      $dt.parse = parse;
      return $dt;
    }
    static create_MinBad() {
      let $dt = new MinM(3);
      return $dt;
    }
    get is_NoMin() { return this.$tag === 0; }
    get is_EqPin() { return this.$tag === 1; }
    get is_Svn() { return this.$tag === 2; }
    get is_MinBad() { return this.$tag === 3; }
    get dtor_matches() { return this.matches; }
    get dtor_parse() { return this.parse; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.MinM.NoMin";
      } else if (this.$tag === 1) {
        return "Attest.MinM.EqPin" + "(" + _dafny.toString(this.matches) + ")";
      } else if (this.$tag === 2) {
        return "Attest.MinM.Svn" + "(" + _dafny.toString(this.parse) + ")";
      } else if (this.$tag === 3) {
        return "Attest.MinM.MinBad";
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
        return other.$tag === 1 && this.matches === other.matches;
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.parse, other.parse);
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.MinM.create_NoMin();
    }
    static Rtd() {
      return class {
        static get Default() {
          return MinM.Default();
        }
      };
    }
  }

  $module.BIdent = class BIdent {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_BIdent(model, weights, weightsMeasured, hasSys, sys, hasTool, tool, operatorMatches) {
      let $dt = new BIdent(0);
      $dt.model = model;
      $dt.weights = weights;
      $dt.weightsMeasured = weightsMeasured;
      $dt.hasSys = hasSys;
      $dt.sys = sys;
      $dt.hasTool = hasTool;
      $dt.tool = tool;
      $dt.operatorMatches = operatorMatches;
      return $dt;
    }
    get is_BIdent() { return this.$tag === 0; }
    get dtor_model() { return this.model; }
    get dtor_weights() { return this.weights; }
    get dtor_weightsMeasured() { return this.weightsMeasured; }
    get dtor_hasSys() { return this.hasSys; }
    get dtor_sys() { return this.sys; }
    get dtor_hasTool() { return this.hasTool; }
    get dtor_tool() { return this.tool; }
    get dtor_operatorMatches() { return this.operatorMatches; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.BIdent.BIdent" + "(" + _dafny.toString(this.model) + ", " + _dafny.toString(this.weights) + ", " + _dafny.toString(this.weightsMeasured) + ", " + _dafny.toString(this.hasSys) + ", " + _dafny.toString(this.sys) + ", " + _dafny.toString(this.hasTool) + ", " + _dafny.toString(this.tool) + ", " + _dafny.toString(this.operatorMatches) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.model, other.model) && _dafny.areEqual(this.weights, other.weights) && this.weightsMeasured === other.weightsMeasured && this.hasSys === other.hasSys && _dafny.areEqual(this.sys, other.sys) && this.hasTool === other.hasTool && _dafny.areEqual(this.tool, other.tool) && this.operatorMatches === other.operatorMatches;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.BIdent.create_BIdent(_dafny.ZERO, _dafny.ZERO, false, false, _dafny.ZERO, false, _dafny.ZERO, false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return BIdent.Default();
        }
      };
    }
  }

  $module.Binding = class Binding {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Binding(modelAllow, minM, operatorPinned, requireMeasured, weightsAllow, sysAllow, toolAllow) {
      let $dt = new Binding(0);
      $dt.modelAllow = modelAllow;
      $dt.minM = minM;
      $dt.operatorPinned = operatorPinned;
      $dt.requireMeasured = requireMeasured;
      $dt.weightsAllow = weightsAllow;
      $dt.sysAllow = sysAllow;
      $dt.toolAllow = toolAllow;
      return $dt;
    }
    get is_Binding() { return this.$tag === 0; }
    get dtor_modelAllow() { return this.modelAllow; }
    get dtor_minM() { return this.minM; }
    get dtor_operatorPinned() { return this.operatorPinned; }
    get dtor_requireMeasured() { return this.requireMeasured; }
    get dtor_weightsAllow() { return this.weightsAllow; }
    get dtor_sysAllow() { return this.sysAllow; }
    get dtor_toolAllow() { return this.toolAllow; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.Binding.Binding" + "(" + _dafny.toString(this.modelAllow) + ", " + _dafny.toString(this.minM) + ", " + _dafny.toString(this.operatorPinned) + ", " + _dafny.toString(this.requireMeasured) + ", " + _dafny.toString(this.weightsAllow) + ", " + _dafny.toString(this.sysAllow) + ", " + _dafny.toString(this.toolAllow) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.modelAllow, other.modelAllow) && _dafny.areEqual(this.minM, other.minM) && this.operatorPinned === other.operatorPinned && this.requireMeasured === other.requireMeasured && _dafny.areEqual(this.weightsAllow, other.weightsAllow) && _dafny.areEqual(this.sysAllow, other.sysAllow) && _dafny.areEqual(this.toolAllow, other.toolAllow);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.Binding.create_Binding(_dafny.Seq.of(), Attest.MinM.Default(), false, false, _dafny.Seq.of(), _dafny.Seq.of(), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Binding.Default();
        }
      };
    }
  }

  $module.BFail = class BFail {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_BModel() {
      let $dt = new BFail(0);
      return $dt;
    }
    static create_BMinBad() {
      let $dt = new BFail(1);
      return $dt;
    }
    static create_BMinEq() {
      let $dt = new BFail(2);
      return $dt;
    }
    static create_BMinSvnNotInt() {
      let $dt = new BFail(3);
      return $dt;
    }
    static create_BMinSvnBelow() {
      let $dt = new BFail(4);
      return $dt;
    }
    static create_BOperator() {
      let $dt = new BFail(5);
      return $dt;
    }
    static create_BNotMeasured() {
      let $dt = new BFail(6);
      return $dt;
    }
    static create_BWeights() {
      let $dt = new BFail(7);
      return $dt;
    }
    static create_BSys() {
      let $dt = new BFail(8);
      return $dt;
    }
    static create_BTool() {
      let $dt = new BFail(9);
      return $dt;
    }
    get is_BModel() { return this.$tag === 0; }
    get is_BMinBad() { return this.$tag === 1; }
    get is_BMinEq() { return this.$tag === 2; }
    get is_BMinSvnNotInt() { return this.$tag === 3; }
    get is_BMinSvnBelow() { return this.$tag === 4; }
    get is_BOperator() { return this.$tag === 5; }
    get is_BNotMeasured() { return this.$tag === 6; }
    get is_BWeights() { return this.$tag === 7; }
    get is_BSys() { return this.$tag === 8; }
    get is_BTool() { return this.$tag === 9; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield BFail.create_BModel();
      yield BFail.create_BMinBad();
      yield BFail.create_BMinEq();
      yield BFail.create_BMinSvnNotInt();
      yield BFail.create_BMinSvnBelow();
      yield BFail.create_BOperator();
      yield BFail.create_BNotMeasured();
      yield BFail.create_BWeights();
      yield BFail.create_BSys();
      yield BFail.create_BTool();
    }
    toString() {
      if (this.$tag === 0) {
        return "Attest.BFail.BModel";
      } else if (this.$tag === 1) {
        return "Attest.BFail.BMinBad";
      } else if (this.$tag === 2) {
        return "Attest.BFail.BMinEq";
      } else if (this.$tag === 3) {
        return "Attest.BFail.BMinSvnNotInt";
      } else if (this.$tag === 4) {
        return "Attest.BFail.BMinSvnBelow";
      } else if (this.$tag === 5) {
        return "Attest.BFail.BOperator";
      } else if (this.$tag === 6) {
        return "Attest.BFail.BNotMeasured";
      } else if (this.$tag === 7) {
        return "Attest.BFail.BWeights";
      } else if (this.$tag === 8) {
        return "Attest.BFail.BSys";
      } else if (this.$tag === 9) {
        return "Attest.BFail.BTool";
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
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else if (this.$tag === 4) {
        return other.$tag === 4;
      } else if (this.$tag === 5) {
        return other.$tag === 5;
      } else if (this.$tag === 6) {
        return other.$tag === 6;
      } else if (this.$tag === 7) {
        return other.$tag === 7;
      } else if (this.$tag === 8) {
        return other.$tag === 8;
      } else if (this.$tag === 9) {
        return other.$tag === 9;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.BFail.create_BModel();
    }
    static Rtd() {
      return class {
        static get Default() {
          return BFail.Default();
        }
      };
    }
  }

  $module.BindingFlags = class BindingFlags {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_BindingFlags(modelAllowNonEmpty, hasMin, operatorNonEmpty, weightsNonEmpty, sysNonEmpty, toolNonEmpty, requireHw, requireMeasured) {
      let $dt = new BindingFlags(0);
      $dt.modelAllowNonEmpty = modelAllowNonEmpty;
      $dt.hasMin = hasMin;
      $dt.operatorNonEmpty = operatorNonEmpty;
      $dt.weightsNonEmpty = weightsNonEmpty;
      $dt.sysNonEmpty = sysNonEmpty;
      $dt.toolNonEmpty = toolNonEmpty;
      $dt.requireHw = requireHw;
      $dt.requireMeasured = requireMeasured;
      return $dt;
    }
    get is_BindingFlags() { return this.$tag === 0; }
    get dtor_modelAllowNonEmpty() { return this.modelAllowNonEmpty; }
    get dtor_hasMin() { return this.hasMin; }
    get dtor_operatorNonEmpty() { return this.operatorNonEmpty; }
    get dtor_weightsNonEmpty() { return this.weightsNonEmpty; }
    get dtor_sysNonEmpty() { return this.sysNonEmpty; }
    get dtor_toolNonEmpty() { return this.toolNonEmpty; }
    get dtor_requireHw() { return this.requireHw; }
    get dtor_requireMeasured() { return this.requireMeasured; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.BindingFlags.BindingFlags" + "(" + _dafny.toString(this.modelAllowNonEmpty) + ", " + _dafny.toString(this.hasMin) + ", " + _dafny.toString(this.operatorNonEmpty) + ", " + _dafny.toString(this.weightsNonEmpty) + ", " + _dafny.toString(this.sysNonEmpty) + ", " + _dafny.toString(this.toolNonEmpty) + ", " + _dafny.toString(this.requireHw) + ", " + _dafny.toString(this.requireMeasured) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.modelAllowNonEmpty === other.modelAllowNonEmpty && this.hasMin === other.hasMin && this.operatorNonEmpty === other.operatorNonEmpty && this.weightsNonEmpty === other.weightsNonEmpty && this.sysNonEmpty === other.sysNonEmpty && this.toolNonEmpty === other.toolNonEmpty && this.requireHw === other.requireHw && this.requireMeasured === other.requireMeasured;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.BindingFlags.create_BindingFlags(false, false, false, false, false, false, false, false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return BindingFlags.Default();
        }
      };
    }
  }

  $module.Kind = class Kind {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_KPresent() {
      let $dt = new Kind(0);
      return $dt;
    }
    static create_KBindingConstructible() {
      let $dt = new Kind(1);
      return $dt;
    }
    static create_KGrantRef() {
      let $dt = new Kind(2);
      return $dt;
    }
    static create_KEpoch() {
      let $dt = new Kind(3);
      return $dt;
    }
    static create_KQuote() {
      let $dt = new Kind(4);
      return $dt;
    }
    static create_KDocNonce() {
      let $dt = new Kind(5);
      return $dt;
    }
    static create_KReqHwVerifier() {
      let $dt = new Kind(6);
      return $dt;
    }
    static create_KReqHwMode() {
      let $dt = new Kind(7);
      return $dt;
    }
    static create_KHwNonceAge() {
      let $dt = new Kind(8);
      return $dt;
    }
    static create_KHwOk() {
      let $dt = new Kind(9);
      return $dt;
    }
    static create_KHwBound() {
      let $dt = new Kind(10);
      return $dt;
    }
    static create_KHwMeasured() {
      let $dt = new Kind(11);
      return $dt;
    }
    static create_KSoftMode() {
      let $dt = new Kind(12);
      return $dt;
    }
    static create_KAttestorTrusted() {
      let $dt = new Kind(13);
      return $dt;
    }
    static create_KAlgKnown() {
      let $dt = new Kind(14);
      return $dt;
    }
    static create_KSigOk() {
      let $dt = new Kind(15);
      return $dt;
    }
    static create_KBindingPresent() {
      let $dt = new Kind(16);
      return $dt;
    }
    static create_KBindingEq() {
      let $dt = new Kind(17);
      return $dt;
    }
    static create_KWindowWellFormed() {
      let $dt = new Kind(18);
      return $dt;
    }
    static create_KNotYetValid() {
      let $dt = new Kind(19);
      return $dt;
    }
    static create_KExpired() {
      let $dt = new Kind(20);
      return $dt;
    }
    static create_KSoftNonceAge() {
      let $dt = new Kind(21);
      return $dt;
    }
    static create_KAgentBinding() {
      let $dt = new Kind(22);
      return $dt;
    }
    get is_KPresent() { return this.$tag === 0; }
    get is_KBindingConstructible() { return this.$tag === 1; }
    get is_KGrantRef() { return this.$tag === 2; }
    get is_KEpoch() { return this.$tag === 3; }
    get is_KQuote() { return this.$tag === 4; }
    get is_KDocNonce() { return this.$tag === 5; }
    get is_KReqHwVerifier() { return this.$tag === 6; }
    get is_KReqHwMode() { return this.$tag === 7; }
    get is_KHwNonceAge() { return this.$tag === 8; }
    get is_KHwOk() { return this.$tag === 9; }
    get is_KHwBound() { return this.$tag === 10; }
    get is_KHwMeasured() { return this.$tag === 11; }
    get is_KSoftMode() { return this.$tag === 12; }
    get is_KAttestorTrusted() { return this.$tag === 13; }
    get is_KAlgKnown() { return this.$tag === 14; }
    get is_KSigOk() { return this.$tag === 15; }
    get is_KBindingPresent() { return this.$tag === 16; }
    get is_KBindingEq() { return this.$tag === 17; }
    get is_KWindowWellFormed() { return this.$tag === 18; }
    get is_KNotYetValid() { return this.$tag === 19; }
    get is_KExpired() { return this.$tag === 20; }
    get is_KSoftNonceAge() { return this.$tag === 21; }
    get is_KAgentBinding() { return this.$tag === 22; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield Kind.create_KPresent();
      yield Kind.create_KBindingConstructible();
      yield Kind.create_KGrantRef();
      yield Kind.create_KEpoch();
      yield Kind.create_KQuote();
      yield Kind.create_KDocNonce();
      yield Kind.create_KReqHwVerifier();
      yield Kind.create_KReqHwMode();
      yield Kind.create_KHwNonceAge();
      yield Kind.create_KHwOk();
      yield Kind.create_KHwBound();
      yield Kind.create_KHwMeasured();
      yield Kind.create_KSoftMode();
      yield Kind.create_KAttestorTrusted();
      yield Kind.create_KAlgKnown();
      yield Kind.create_KSigOk();
      yield Kind.create_KBindingPresent();
      yield Kind.create_KBindingEq();
      yield Kind.create_KWindowWellFormed();
      yield Kind.create_KNotYetValid();
      yield Kind.create_KExpired();
      yield Kind.create_KSoftNonceAge();
      yield Kind.create_KAgentBinding();
    }
    toString() {
      if (this.$tag === 0) {
        return "Attest.Kind.KPresent";
      } else if (this.$tag === 1) {
        return "Attest.Kind.KBindingConstructible";
      } else if (this.$tag === 2) {
        return "Attest.Kind.KGrantRef";
      } else if (this.$tag === 3) {
        return "Attest.Kind.KEpoch";
      } else if (this.$tag === 4) {
        return "Attest.Kind.KQuote";
      } else if (this.$tag === 5) {
        return "Attest.Kind.KDocNonce";
      } else if (this.$tag === 6) {
        return "Attest.Kind.KReqHwVerifier";
      } else if (this.$tag === 7) {
        return "Attest.Kind.KReqHwMode";
      } else if (this.$tag === 8) {
        return "Attest.Kind.KHwNonceAge";
      } else if (this.$tag === 9) {
        return "Attest.Kind.KHwOk";
      } else if (this.$tag === 10) {
        return "Attest.Kind.KHwBound";
      } else if (this.$tag === 11) {
        return "Attest.Kind.KHwMeasured";
      } else if (this.$tag === 12) {
        return "Attest.Kind.KSoftMode";
      } else if (this.$tag === 13) {
        return "Attest.Kind.KAttestorTrusted";
      } else if (this.$tag === 14) {
        return "Attest.Kind.KAlgKnown";
      } else if (this.$tag === 15) {
        return "Attest.Kind.KSigOk";
      } else if (this.$tag === 16) {
        return "Attest.Kind.KBindingPresent";
      } else if (this.$tag === 17) {
        return "Attest.Kind.KBindingEq";
      } else if (this.$tag === 18) {
        return "Attest.Kind.KWindowWellFormed";
      } else if (this.$tag === 19) {
        return "Attest.Kind.KNotYetValid";
      } else if (this.$tag === 20) {
        return "Attest.Kind.KExpired";
      } else if (this.$tag === 21) {
        return "Attest.Kind.KSoftNonceAge";
      } else if (this.$tag === 22) {
        return "Attest.Kind.KAgentBinding";
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
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else if (this.$tag === 4) {
        return other.$tag === 4;
      } else if (this.$tag === 5) {
        return other.$tag === 5;
      } else if (this.$tag === 6) {
        return other.$tag === 6;
      } else if (this.$tag === 7) {
        return other.$tag === 7;
      } else if (this.$tag === 8) {
        return other.$tag === 8;
      } else if (this.$tag === 9) {
        return other.$tag === 9;
      } else if (this.$tag === 10) {
        return other.$tag === 10;
      } else if (this.$tag === 11) {
        return other.$tag === 11;
      } else if (this.$tag === 12) {
        return other.$tag === 12;
      } else if (this.$tag === 13) {
        return other.$tag === 13;
      } else if (this.$tag === 14) {
        return other.$tag === 14;
      } else if (this.$tag === 15) {
        return other.$tag === 15;
      } else if (this.$tag === 16) {
        return other.$tag === 16;
      } else if (this.$tag === 17) {
        return other.$tag === 17;
      } else if (this.$tag === 18) {
        return other.$tag === 18;
      } else if (this.$tag === 19) {
        return other.$tag === 19;
      } else if (this.$tag === 20) {
        return other.$tag === 20;
      } else if (this.$tag === 21) {
        return other.$tag === 21;
      } else if (this.$tag === 22) {
        return other.$tag === 22;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.Kind.create_KPresent();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Kind.Default();
        }
      };
    }
  }

  $module.VFacts = class VFacts {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_VFacts(present, bindingConstructible, grantRefOk, epochOk, quoteOk, docNonceOk, requireHw, hasHwVerifier, docIsHardware, hwNonceAgeOk, hwOk, hwBound, hwHasMeasured, docIsSoftware, attestorTrusted, algKnown, sigOk, bindingPresent, bindingEq, windowWellFormed, notYetValid, expired, hasNonceIssuedAt, softNonceAgeOk, agentBindingOk) {
      let $dt = new VFacts(0);
      $dt.present = present;
      $dt.bindingConstructible = bindingConstructible;
      $dt.grantRefOk = grantRefOk;
      $dt.epochOk = epochOk;
      $dt.quoteOk = quoteOk;
      $dt.docNonceOk = docNonceOk;
      $dt.requireHw = requireHw;
      $dt.hasHwVerifier = hasHwVerifier;
      $dt.docIsHardware = docIsHardware;
      $dt.hwNonceAgeOk = hwNonceAgeOk;
      $dt.hwOk = hwOk;
      $dt.hwBound = hwBound;
      $dt.hwHasMeasured = hwHasMeasured;
      $dt.docIsSoftware = docIsSoftware;
      $dt.attestorTrusted = attestorTrusted;
      $dt.algKnown = algKnown;
      $dt.sigOk = sigOk;
      $dt.bindingPresent = bindingPresent;
      $dt.bindingEq = bindingEq;
      $dt.windowWellFormed = windowWellFormed;
      $dt.notYetValid = notYetValid;
      $dt.expired = expired;
      $dt.hasNonceIssuedAt = hasNonceIssuedAt;
      $dt.softNonceAgeOk = softNonceAgeOk;
      $dt.agentBindingOk = agentBindingOk;
      return $dt;
    }
    get is_VFacts() { return this.$tag === 0; }
    get dtor_present() { return this.present; }
    get dtor_bindingConstructible() { return this.bindingConstructible; }
    get dtor_grantRefOk() { return this.grantRefOk; }
    get dtor_epochOk() { return this.epochOk; }
    get dtor_quoteOk() { return this.quoteOk; }
    get dtor_docNonceOk() { return this.docNonceOk; }
    get dtor_requireHw() { return this.requireHw; }
    get dtor_hasHwVerifier() { return this.hasHwVerifier; }
    get dtor_docIsHardware() { return this.docIsHardware; }
    get dtor_hwNonceAgeOk() { return this.hwNonceAgeOk; }
    get dtor_hwOk() { return this.hwOk; }
    get dtor_hwBound() { return this.hwBound; }
    get dtor_hwHasMeasured() { return this.hwHasMeasured; }
    get dtor_docIsSoftware() { return this.docIsSoftware; }
    get dtor_attestorTrusted() { return this.attestorTrusted; }
    get dtor_algKnown() { return this.algKnown; }
    get dtor_sigOk() { return this.sigOk; }
    get dtor_bindingPresent() { return this.bindingPresent; }
    get dtor_bindingEq() { return this.bindingEq; }
    get dtor_windowWellFormed() { return this.windowWellFormed; }
    get dtor_notYetValid() { return this.notYetValid; }
    get dtor_expired() { return this.expired; }
    get dtor_hasNonceIssuedAt() { return this.hasNonceIssuedAt; }
    get dtor_softNonceAgeOk() { return this.softNonceAgeOk; }
    get dtor_agentBindingOk() { return this.agentBindingOk; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.VFacts.VFacts" + "(" + _dafny.toString(this.present) + ", " + _dafny.toString(this.bindingConstructible) + ", " + _dafny.toString(this.grantRefOk) + ", " + _dafny.toString(this.epochOk) + ", " + _dafny.toString(this.quoteOk) + ", " + _dafny.toString(this.docNonceOk) + ", " + _dafny.toString(this.requireHw) + ", " + _dafny.toString(this.hasHwVerifier) + ", " + _dafny.toString(this.docIsHardware) + ", " + _dafny.toString(this.hwNonceAgeOk) + ", " + _dafny.toString(this.hwOk) + ", " + _dafny.toString(this.hwBound) + ", " + _dafny.toString(this.hwHasMeasured) + ", " + _dafny.toString(this.docIsSoftware) + ", " + _dafny.toString(this.attestorTrusted) + ", " + _dafny.toString(this.algKnown) + ", " + _dafny.toString(this.sigOk) + ", " + _dafny.toString(this.bindingPresent) + ", " + _dafny.toString(this.bindingEq) + ", " + _dafny.toString(this.windowWellFormed) + ", " + _dafny.toString(this.notYetValid) + ", " + _dafny.toString(this.expired) + ", " + _dafny.toString(this.hasNonceIssuedAt) + ", " + _dafny.toString(this.softNonceAgeOk) + ", " + _dafny.toString(this.agentBindingOk) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.present === other.present && this.bindingConstructible === other.bindingConstructible && this.grantRefOk === other.grantRefOk && this.epochOk === other.epochOk && this.quoteOk === other.quoteOk && this.docNonceOk === other.docNonceOk && this.requireHw === other.requireHw && this.hasHwVerifier === other.hasHwVerifier && this.docIsHardware === other.docIsHardware && this.hwNonceAgeOk === other.hwNonceAgeOk && this.hwOk === other.hwOk && this.hwBound === other.hwBound && this.hwHasMeasured === other.hwHasMeasured && this.docIsSoftware === other.docIsSoftware && this.attestorTrusted === other.attestorTrusted && this.algKnown === other.algKnown && this.sigOk === other.sigOk && this.bindingPresent === other.bindingPresent && this.bindingEq === other.bindingEq && this.windowWellFormed === other.windowWellFormed && this.notYetValid === other.notYetValid && this.expired === other.expired && this.hasNonceIssuedAt === other.hasNonceIssuedAt && this.softNonceAgeOk === other.softNonceAgeOk && this.agentBindingOk === other.agentBindingOk;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.VFacts.create_VFacts(false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return VFacts.Default();
        }
      };
    }
  }

  $module.AgeRes = class AgeRes {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_AgeUnknown() {
      let $dt = new AgeRes(0);
      return $dt;
    }
    static create_AgeFuture() {
      let $dt = new AgeRes(1);
      return $dt;
    }
    static create_AgeStale() {
      let $dt = new AgeRes(2);
      return $dt;
    }
    static create_AgeFresh() {
      let $dt = new AgeRes(3);
      return $dt;
    }
    get is_AgeUnknown() { return this.$tag === 0; }
    get is_AgeFuture() { return this.$tag === 1; }
    get is_AgeStale() { return this.$tag === 2; }
    get is_AgeFresh() { return this.$tag === 3; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield AgeRes.create_AgeUnknown();
      yield AgeRes.create_AgeFuture();
      yield AgeRes.create_AgeStale();
      yield AgeRes.create_AgeFresh();
    }
    toString() {
      if (this.$tag === 0) {
        return "Attest.AgeRes.AgeUnknown";
      } else if (this.$tag === 1) {
        return "Attest.AgeRes.AgeFuture";
      } else if (this.$tag === 2) {
        return "Attest.AgeRes.AgeStale";
      } else if (this.$tag === 3) {
        return "Attest.AgeRes.AgeFresh";
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
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.AgeRes.create_AgeUnknown();
    }
    static Rtd() {
      return class {
        static get Default() {
          return AgeRes.Default();
        }
      };
    }
  }

  $module.WinRes = class WinRes {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_WinMalformed() {
      let $dt = new WinRes(0);
      return $dt;
    }
    static create_WinNotYet() {
      let $dt = new WinRes(1);
      return $dt;
    }
    static create_WinExpired() {
      let $dt = new WinRes(2);
      return $dt;
    }
    static create_WinValid() {
      let $dt = new WinRes(3);
      return $dt;
    }
    get is_WinMalformed() { return this.$tag === 0; }
    get is_WinNotYet() { return this.$tag === 1; }
    get is_WinExpired() { return this.$tag === 2; }
    get is_WinValid() { return this.$tag === 3; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield WinRes.create_WinMalformed();
      yield WinRes.create_WinNotYet();
      yield WinRes.create_WinExpired();
      yield WinRes.create_WinValid();
    }
    toString() {
      if (this.$tag === 0) {
        return "Attest.WinRes.WinMalformed";
      } else if (this.$tag === 1) {
        return "Attest.WinRes.WinNotYet";
      } else if (this.$tag === 2) {
        return "Attest.WinRes.WinExpired";
      } else if (this.$tag === 3) {
        return "Attest.WinRes.WinValid";
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
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.WinRes.create_WinMalformed();
    }
    static Rtd() {
      return class {
        static get Default() {
          return WinRes.Default();
        }
      };
    }
  }

  $module.HookOut = class HookOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_HookOk() {
      let $dt = new HookOut(0);
      return $dt;
    }
    static create_HookVerdictFail() {
      let $dt = new HookOut(1);
      return $dt;
    }
    static create_HookReplay() {
      let $dt = new HookOut(2);
      return $dt;
    }
    get is_HookOk() { return this.$tag === 0; }
    get is_HookVerdictFail() { return this.$tag === 1; }
    get is_HookReplay() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield HookOut.create_HookOk();
      yield HookOut.create_HookVerdictFail();
      yield HookOut.create_HookReplay();
    }
    toString() {
      if (this.$tag === 0) {
        return "Attest.HookOut.HookOk";
      } else if (this.$tag === 1) {
        return "Attest.HookOut.HookVerdictFail";
      } else if (this.$tag === 2) {
        return "Attest.HookOut.HookReplay";
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
      return Attest.HookOut.create_HookOk();
    }
    static Rtd() {
      return class {
        static get Default() {
          return HookOut.Default();
        }
      };
    }
  }

  $module.MS = class MS {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_MS(items, max, ret) {
      let $dt = new MS(0);
      $dt.items = items;
      $dt.max = max;
      $dt.ret = ret;
      return $dt;
    }
    get is_MS() { return this.$tag === 0; }
    get dtor_items() { return this.items; }
    get dtor_max() { return this.max; }
    get dtor_ret() { return this.ret; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.MS.MS" + "(" + _dafny.toString(this.items) + ", " + _dafny.toString(this.max) + ", " + _dafny.toString(this.ret) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.items, other.items) && _dafny.areEqual(this.max, other.max) && _dafny.areEqual(this.ret, other.ret);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.MS.create_MS(_dafny.Seq.of(), _dafny.ZERO, _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return MS.Default();
        }
      };
    }
  }

  $module.AKind = class AKind {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_ASshape() {
      let $dt = new AKind(0);
      return $dt;
    }
    static create_AUnknownIssuer() {
      let $dt = new AKind(1);
      return $dt;
    }
    static create_AAlgMismatch() {
      let $dt = new AKind(2);
      return $dt;
    }
    static create_AIssuerExpired() {
      let $dt = new AKind(3);
      return $dt;
    }
    static create_ABadSig() {
      let $dt = new AKind(4);
      return $dt;
    }
    static create_AOptions() {
      let $dt = new AKind(5);
      return $dt;
    }
    static create_ANotYet() {
      let $dt = new AKind(6);
      return $dt;
    }
    static create_AExpired() {
      let $dt = new AKind(7);
      return $dt;
    }
    static create_ALifetime() {
      let $dt = new AKind(8);
      return $dt;
    }
    static create_ABelowMin() {
      let $dt = new AKind(9);
      return $dt;
    }
    static create_ARollback() {
      let $dt = new AKind(10);
      return $dt;
    }
    static create_AConflict() {
      let $dt = new AKind(11);
      return $dt;
    }
    get is_ASshape() { return this.$tag === 0; }
    get is_AUnknownIssuer() { return this.$tag === 1; }
    get is_AAlgMismatch() { return this.$tag === 2; }
    get is_AIssuerExpired() { return this.$tag === 3; }
    get is_ABadSig() { return this.$tag === 4; }
    get is_AOptions() { return this.$tag === 5; }
    get is_ANotYet() { return this.$tag === 6; }
    get is_AExpired() { return this.$tag === 7; }
    get is_ALifetime() { return this.$tag === 8; }
    get is_ABelowMin() { return this.$tag === 9; }
    get is_ARollback() { return this.$tag === 10; }
    get is_AConflict() { return this.$tag === 11; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield AKind.create_ASshape();
      yield AKind.create_AUnknownIssuer();
      yield AKind.create_AAlgMismatch();
      yield AKind.create_AIssuerExpired();
      yield AKind.create_ABadSig();
      yield AKind.create_AOptions();
      yield AKind.create_ANotYet();
      yield AKind.create_AExpired();
      yield AKind.create_ALifetime();
      yield AKind.create_ABelowMin();
      yield AKind.create_ARollback();
      yield AKind.create_AConflict();
    }
    toString() {
      if (this.$tag === 0) {
        return "Attest.AKind.ASshape";
      } else if (this.$tag === 1) {
        return "Attest.AKind.AUnknownIssuer";
      } else if (this.$tag === 2) {
        return "Attest.AKind.AAlgMismatch";
      } else if (this.$tag === 3) {
        return "Attest.AKind.AIssuerExpired";
      } else if (this.$tag === 4) {
        return "Attest.AKind.ABadSig";
      } else if (this.$tag === 5) {
        return "Attest.AKind.AOptions";
      } else if (this.$tag === 6) {
        return "Attest.AKind.ANotYet";
      } else if (this.$tag === 7) {
        return "Attest.AKind.AExpired";
      } else if (this.$tag === 8) {
        return "Attest.AKind.ALifetime";
      } else if (this.$tag === 9) {
        return "Attest.AKind.ABelowMin";
      } else if (this.$tag === 10) {
        return "Attest.AKind.ARollback";
      } else if (this.$tag === 11) {
        return "Attest.AKind.AConflict";
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
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else if (this.$tag === 4) {
        return other.$tag === 4;
      } else if (this.$tag === 5) {
        return other.$tag === 5;
      } else if (this.$tag === 6) {
        return other.$tag === 6;
      } else if (this.$tag === 7) {
        return other.$tag === 7;
      } else if (this.$tag === 8) {
        return other.$tag === 8;
      } else if (this.$tag === 9) {
        return other.$tag === 9;
      } else if (this.$tag === 10) {
        return other.$tag === 10;
      } else if (this.$tag === 11) {
        return other.$tag === 11;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.AKind.create_ASshape();
    }
    static Rtd() {
      return class {
        static get Default() {
          return AKind.Default();
        }
      };
    }
  }

  $module.AFacts = class AFacts {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_AFacts(shapeOk, issuerKnown, algMatches, issuerLive, sigOk, optionsOk, now, skew, notBefore, expiresAt, hasMaxLife, maxLife, hasMin, minV, version, hasLast, lastV, hasLastDigest, lastDigest, digest) {
      let $dt = new AFacts(0);
      $dt.shapeOk = shapeOk;
      $dt.issuerKnown = issuerKnown;
      $dt.algMatches = algMatches;
      $dt.issuerLive = issuerLive;
      $dt.sigOk = sigOk;
      $dt.optionsOk = optionsOk;
      $dt.now = now;
      $dt.skew = skew;
      $dt.notBefore = notBefore;
      $dt.expiresAt = expiresAt;
      $dt.hasMaxLife = hasMaxLife;
      $dt.maxLife = maxLife;
      $dt.hasMin = hasMin;
      $dt.minV = minV;
      $dt.version = version;
      $dt.hasLast = hasLast;
      $dt.lastV = lastV;
      $dt.hasLastDigest = hasLastDigest;
      $dt.lastDigest = lastDigest;
      $dt.digest = digest;
      return $dt;
    }
    get is_AFacts() { return this.$tag === 0; }
    get dtor_shapeOk() { return this.shapeOk; }
    get dtor_issuerKnown() { return this.issuerKnown; }
    get dtor_algMatches() { return this.algMatches; }
    get dtor_issuerLive() { return this.issuerLive; }
    get dtor_sigOk() { return this.sigOk; }
    get dtor_optionsOk() { return this.optionsOk; }
    get dtor_now() { return this.now; }
    get dtor_skew() { return this.skew; }
    get dtor_notBefore() { return this.notBefore; }
    get dtor_expiresAt() { return this.expiresAt; }
    get dtor_hasMaxLife() { return this.hasMaxLife; }
    get dtor_maxLife() { return this.maxLife; }
    get dtor_hasMin() { return this.hasMin; }
    get dtor_minV() { return this.minV; }
    get dtor_version() { return this.version; }
    get dtor_hasLast() { return this.hasLast; }
    get dtor_lastV() { return this.lastV; }
    get dtor_hasLastDigest() { return this.hasLastDigest; }
    get dtor_lastDigest() { return this.lastDigest; }
    get dtor_digest() { return this.digest; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.AFacts.AFacts" + "(" + _dafny.toString(this.shapeOk) + ", " + _dafny.toString(this.issuerKnown) + ", " + _dafny.toString(this.algMatches) + ", " + _dafny.toString(this.issuerLive) + ", " + _dafny.toString(this.sigOk) + ", " + _dafny.toString(this.optionsOk) + ", " + _dafny.toString(this.now) + ", " + _dafny.toString(this.skew) + ", " + _dafny.toString(this.notBefore) + ", " + _dafny.toString(this.expiresAt) + ", " + _dafny.toString(this.hasMaxLife) + ", " + _dafny.toString(this.maxLife) + ", " + _dafny.toString(this.hasMin) + ", " + _dafny.toString(this.minV) + ", " + _dafny.toString(this.version) + ", " + _dafny.toString(this.hasLast) + ", " + _dafny.toString(this.lastV) + ", " + _dafny.toString(this.hasLastDigest) + ", " + _dafny.toString(this.lastDigest) + ", " + _dafny.toString(this.digest) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.shapeOk === other.shapeOk && this.issuerKnown === other.issuerKnown && this.algMatches === other.algMatches && this.issuerLive === other.issuerLive && this.sigOk === other.sigOk && this.optionsOk === other.optionsOk && _dafny.areEqual(this.now, other.now) && _dafny.areEqual(this.skew, other.skew) && _dafny.areEqual(this.notBefore, other.notBefore) && _dafny.areEqual(this.expiresAt, other.expiresAt) && this.hasMaxLife === other.hasMaxLife && _dafny.areEqual(this.maxLife, other.maxLife) && this.hasMin === other.hasMin && _dafny.areEqual(this.minV, other.minV) && _dafny.areEqual(this.version, other.version) && this.hasLast === other.hasLast && _dafny.areEqual(this.lastV, other.lastV) && this.hasLastDigest === other.hasLastDigest && _dafny.areEqual(this.lastDigest, other.lastDigest) && _dafny.areEqual(this.digest, other.digest);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.AFacts.create_AFacts(false, false, false, false, false, false, _dafny.ZERO, _dafny.ZERO, _dafny.ZERO, _dafny.ZERO, false, _dafny.ZERO, false, _dafny.ZERO, _dafny.ZERO, false, _dafny.ZERO, false, _dafny.ZERO, _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return AFacts.Default();
        }
      };
    }
  }

  $module.KV = class KV {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_KMissing() {
      let $dt = new KV(0);
      return $dt;
    }
    static create_KCorrupt() {
      let $dt = new KV(1);
      return $dt;
    }
    static create_KVal(v, d) {
      let $dt = new KV(2);
      $dt.v = v;
      $dt.d = d;
      return $dt;
    }
    get is_KMissing() { return this.$tag === 0; }
    get is_KCorrupt() { return this.$tag === 1; }
    get is_KVal() { return this.$tag === 2; }
    get dtor_v() { return this.v; }
    get dtor_d() { return this.d; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.KV.KMissing";
      } else if (this.$tag === 1) {
        return "Attest.KV.KCorrupt";
      } else if (this.$tag === 2) {
        return "Attest.KV.KVal" + "(" + _dafny.toString(this.v) + ", " + _dafny.toString(this.d) + ")";
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
        return other.$tag === 2 && _dafny.areEqual(this.v, other.v) && _dafny.areEqual(this.d, other.d);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.KV.create_KMissing();
    }
    static Rtd() {
      return class {
        static get Default() {
          return KV.Default();
        }
      };
    }
  }

  $module.DOut = class DOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_DAccept() {
      let $dt = new DOut(0);
      return $dt;
    }
    static create_DMalformed() {
      let $dt = new DOut(1);
      return $dt;
    }
    static create_DVerifyFail() {
      let $dt = new DOut(2);
      return $dt;
    }
    static create_DRollback() {
      let $dt = new DOut(3);
      return $dt;
    }
    static create_DConflict() {
      let $dt = new DOut(4);
      return $dt;
    }
    get is_DAccept() { return this.$tag === 0; }
    get is_DMalformed() { return this.$tag === 1; }
    get is_DVerifyFail() { return this.$tag === 2; }
    get is_DRollback() { return this.$tag === 3; }
    get is_DConflict() { return this.$tag === 4; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield DOut.create_DAccept();
      yield DOut.create_DMalformed();
      yield DOut.create_DVerifyFail();
      yield DOut.create_DRollback();
      yield DOut.create_DConflict();
    }
    toString() {
      if (this.$tag === 0) {
        return "Attest.DOut.DAccept";
      } else if (this.$tag === 1) {
        return "Attest.DOut.DMalformed";
      } else if (this.$tag === 2) {
        return "Attest.DOut.DVerifyFail";
      } else if (this.$tag === 3) {
        return "Attest.DOut.DRollback";
      } else if (this.$tag === 4) {
        return "Attest.DOut.DConflict";
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
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else if (this.$tag === 4) {
        return other.$tag === 4;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.DOut.create_DAccept();
    }
    static Rtd() {
      return class {
        static get Default() {
          return DOut.Default();
        }
      };
    }
  }

  $module.DOp = class DOp {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_DOp(read, verifyOk, v, d) {
      let $dt = new DOp(0);
      $dt.read = read;
      $dt.verifyOk = verifyOk;
      $dt.v = v;
      $dt.d = d;
      return $dt;
    }
    get is_DOp() { return this.$tag === 0; }
    get dtor_read() { return this.read; }
    get dtor_verifyOk() { return this.verifyOk; }
    get dtor_v() { return this.v; }
    get dtor_d() { return this.d; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.DOp.DOp" + "(" + _dafny.toString(this.read) + ", " + _dafny.toString(this.verifyOk) + ", " + _dafny.toString(this.v) + ", " + _dafny.toString(this.d) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.read, other.read) && this.verifyOk === other.verifyOk && _dafny.areEqual(this.v, other.v) && _dafny.areEqual(this.d, other.d);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.DOp.create_DOp(Attest.KV.Default(), false, _dafny.ZERO, _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return DOp.Default();
        }
      };
    }
  }

  $module.AEntry = class AEntry {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_AEntry(issuer, version, digest) {
      let $dt = new AEntry(0);
      $dt.issuer = issuer;
      $dt.version = version;
      $dt.digest = digest;
      return $dt;
    }
    get is_AEntry() { return this.$tag === 0; }
    get dtor_issuer() { return this.issuer; }
    get dtor_version() { return this.version; }
    get dtor_digest() { return this.digest; }
    toString() {
      if (this.$tag === 0) {
        return "Attest.AEntry.AEntry" + "(" + _dafny.toString(this.issuer) + ", " + _dafny.toString(this.version) + ", " + _dafny.toString(this.digest) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.issuer, other.issuer) && _dafny.areEqual(this.version, other.version) && _dafny.areEqual(this.digest, other.digest);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.AEntry.create_AEntry(_dafny.ZERO, _dafny.ZERO, _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return AEntry.Default();
        }
      };
    }
  }

  $module.AnchorFail = class AnchorFail {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_ALogConflict() {
      let $dt = new AnchorFail(0);
      return $dt;
    }
    static create_AAnchoredRollback() {
      let $dt = new AnchorFail(1);
      return $dt;
    }
    static create_ANotAnchored() {
      let $dt = new AnchorFail(2);
      return $dt;
    }
    get is_ALogConflict() { return this.$tag === 0; }
    get is_AAnchoredRollback() { return this.$tag === 1; }
    get is_ANotAnchored() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield AnchorFail.create_ALogConflict();
      yield AnchorFail.create_AAnchoredRollback();
      yield AnchorFail.create_ANotAnchored();
    }
    toString() {
      if (this.$tag === 0) {
        return "Attest.AnchorFail.ALogConflict";
      } else if (this.$tag === 1) {
        return "Attest.AnchorFail.AAnchoredRollback";
      } else if (this.$tag === 2) {
        return "Attest.AnchorFail.ANotAnchored";
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
      return Attest.AnchorFail.create_ALogConflict();
    }
    static Rtd() {
      return class {
        static get Default() {
          return AnchorFail.Default();
        }
      };
    }
  }

  $module.CacheOut = class CacheOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_CacheNone() {
      let $dt = new CacheOut(0);
      return $dt;
    }
    static create_CacheRollback() {
      let $dt = new CacheOut(1);
      return $dt;
    }
    static create_CacheSplitView() {
      let $dt = new CacheOut(2);
      return $dt;
    }
    static create_CacheNeedConsistency() {
      let $dt = new CacheOut(3);
      return $dt;
    }
    static create_CacheOk() {
      let $dt = new CacheOut(4);
      return $dt;
    }
    get is_CacheNone() { return this.$tag === 0; }
    get is_CacheRollback() { return this.$tag === 1; }
    get is_CacheSplitView() { return this.$tag === 2; }
    get is_CacheNeedConsistency() { return this.$tag === 3; }
    get is_CacheOk() { return this.$tag === 4; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield CacheOut.create_CacheNone();
      yield CacheOut.create_CacheRollback();
      yield CacheOut.create_CacheSplitView();
      yield CacheOut.create_CacheNeedConsistency();
      yield CacheOut.create_CacheOk();
    }
    toString() {
      if (this.$tag === 0) {
        return "Attest.CacheOut.CacheNone";
      } else if (this.$tag === 1) {
        return "Attest.CacheOut.CacheRollback";
      } else if (this.$tag === 2) {
        return "Attest.CacheOut.CacheSplitView";
      } else if (this.$tag === 3) {
        return "Attest.CacheOut.CacheNeedConsistency";
      } else if (this.$tag === 4) {
        return "Attest.CacheOut.CacheOk";
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
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else if (this.$tag === 4) {
        return other.$tag === 4;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.CacheOut.create_CacheNone();
    }
    static Rtd() {
      return class {
        static get Default() {
          return CacheOut.Default();
        }
      };
    }
  }

  $module.HeadAge = class HeadAge {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_HeadBadOptions() {
      let $dt = new HeadAge(0);
      return $dt;
    }
    static create_HeadFuture() {
      let $dt = new HeadAge(1);
      return $dt;
    }
    static create_HeadStale() {
      let $dt = new HeadAge(2);
      return $dt;
    }
    static create_HeadFresh() {
      let $dt = new HeadAge(3);
      return $dt;
    }
    get is_HeadBadOptions() { return this.$tag === 0; }
    get is_HeadFuture() { return this.$tag === 1; }
    get is_HeadStale() { return this.$tag === 2; }
    get is_HeadFresh() { return this.$tag === 3; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield HeadAge.create_HeadBadOptions();
      yield HeadAge.create_HeadFuture();
      yield HeadAge.create_HeadStale();
      yield HeadAge.create_HeadFresh();
    }
    toString() {
      if (this.$tag === 0) {
        return "Attest.HeadAge.HeadBadOptions";
      } else if (this.$tag === 1) {
        return "Attest.HeadAge.HeadFuture";
      } else if (this.$tag === 2) {
        return "Attest.HeadAge.HeadStale";
      } else if (this.$tag === 3) {
        return "Attest.HeadAge.HeadFresh";
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
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Attest.HeadAge.create_HeadBadOptions();
    }
    static Rtd() {
      return class {
        static get Default() {
          return HeadAge.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module Attest
let _module = (function() {
  let $module = {};

  return $module;
})(); // end of module _module

// ---- exports (appended by formal/dafny/build-ext.sh) ----
module.exports = { _dafny, Attest };
