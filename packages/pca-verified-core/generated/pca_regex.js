// Dafny program Regex.dfy compiled into JavaScript
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
let Regex = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Regex._default";
    }
    _parentTraits() {
      return [];
    }
    static InRanges(rs, c) {
      if ((new BigNumber((rs).length)).isEqualTo(_dafny.ZERO)) {
        return false;
      } else {
        return (((((rs)[_dafny.ZERO])[0]).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(((rs)[_dafny.ZERO])[1]))) || (Regex.__default.InRanges((rs).slice(_dafny.ONE), c));
      }
    };
    static ItemHas(it, c) {
      let _source0 = it;
      {
        if (_source0.is_Rng) {
          let _0_lo = (_source0).lo;
          let _1_hi = (_source0).hi;
          return ((_0_lo).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(_1_hi));
        }
      }
      {
        if (_source0.is_In) {
          let _2_rs = (_source0).rs;
          return Regex.__default.InRanges(_2_rs, c);
        }
      }
      {
        let _3_rs = (_source0).rs;
        return !(Regex.__default.InRanges(_3_rs, c));
      }
    };
    static AnyItem(items, c) {
      if ((new BigNumber((items).length)).isEqualTo(_dafny.ZERO)) {
        return false;
      } else {
        return (Regex.__default.ItemHas((items)[_dafny.ZERO], c)) || (Regex.__default.AnyItem((items).slice(_dafny.ONE), c));
      }
    };
    static SetHas(cs, c) {
      return (Regex.__default.AnyItem((cs).dtor_items, c)) !== ((cs).dtor_neg);
    };
    static ValidN(n) {
      let _source0 = n;
      {
        if (_source0.is_Set) {
          return true;
        }
      }
      {
        if (_source0.is_Bol) {
          return true;
        }
      }
      {
        if (_source0.is_Eol) {
          return true;
        }
      }
      {
        if (_source0.is_Cat) {
          let _0_l = (_source0).cat;
          return Regex.__default.ValidL(_0_l);
        }
      }
      {
        if (_source0.is_Alt) {
          let _1_l = (_source0).alt;
          return ((_1_l).is_Cons) && (Regex.__default.ValidL(_1_l));
        }
      }
      {
        let _2_inner = (_source0).inner;
        let _3_mn = (_source0).mn;
        let _4_mx = (_source0).mx;
        return ((((Regex.__default.ValidN(_2_inner)) && ((_dafny.ZERO).isLessThanOrEqualTo(_3_mn))) && (((_4_mx).isEqualTo(new BigNumber(-1))) || ((_3_mn).isLessThanOrEqualTo(_4_mx)))) && (!((_2_inner).is_Bol))) && (!((_2_inner).is_Eol));
      }
    };
    static ValidL(l) {
      let _source0 = l;
      {
        if (_source0.is_Nil) {
          return true;
        }
      }
      {
        let _0_h = (_source0).hd;
        let _1_t = (_source0).tl;
        return (Regex.__default.ValidN(_0_h)) && (Regex.__default.ValidL(_1_t));
      }
    };
    static BoundedN(n) {
      let _source0 = n;
      {
        if (_source0.is_Set) {
          return true;
        }
      }
      {
        if (_source0.is_Bol) {
          return true;
        }
      }
      {
        if (_source0.is_Eol) {
          return true;
        }
      }
      {
        if (_source0.is_Cat) {
          let _0_l = (_source0).cat;
          return Regex.__default.BoundedL(_0_l);
        }
      }
      {
        if (_source0.is_Alt) {
          let _1_l = (_source0).alt;
          return Regex.__default.BoundedL(_1_l);
        }
      }
      {
        let _2_inner = (_source0).inner;
        let _3_mn = (_source0).mn;
        let _4_mx = (_source0).mx;
        return ((Regex.__default.BoundedN(_2_inner)) && ((_3_mn).isLessThanOrEqualTo(new BigNumber(64)))) && ((_4_mx).isLessThanOrEqualTo(new BigNumber(64)));
      }
    };
    static BoundedL(l) {
      let _source0 = l;
      {
        if (_source0.is_Nil) {
          return true;
        }
      }
      {
        let _0_h = (_source0).hd;
        let _1_t = (_source0).tl;
        return (Regex.__default.BoundedN(_0_h)) && (Regex.__default.BoundedL(_1_t));
      }
    };
    static IsDigit(c) {
      return ((new BigNumber(48)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(57)));
    };
    static IsHex(c) {
      return ((Regex.__default.IsDigit(c)) || (((new BigNumber(65)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(70))))) || (((new BigNumber(97)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(102))));
    };
    static IsAlpha(c) {
      return (((new BigNumber(65)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(90)))) || (((new BigNumber(97)).isLessThanOrEqualTo(c)) && ((c).isLessThanOrEqualTo(new BigNumber(122))));
    };
    static IsAlnum(c) {
      return (Regex.__default.IsDigit(c)) || (Regex.__default.IsAlpha(c));
    };
    static HexVal(c) {
      if (Regex.__default.IsDigit(c)) {
        return (c).minus(new BigNumber(48));
      } else if ((c).isLessThanOrEqualTo(new BigNumber(70))) {
        return ((c).minus(new BigNumber(65))).plus(new BigNumber(10));
      } else {
        return ((c).minus(new BigNumber(97))).plus(new BigNumber(10));
      }
    };
    static DigitRun(s, p) {
      TAIL_CALL_START: while (true) {
        if (((p).isLessThan(new BigNumber((s).length))) && (Regex.__default.IsDigit((s)[p]))) {
          let _in0 = s;
          let _in1 = (p).plus(_dafny.ONE);
          s = _in0;
          p = _in1;
          continue TAIL_CALL_START;
        } else {
          return p;
        }
      }
    };
    static DigitVal(s, p, q) {
      if ((p).isEqualTo(q)) {
        return _dafny.ZERO;
      } else {
        return ((Regex.__default.DigitVal(s, p, (q).minus(_dafny.ONE))).multipliedBy(new BigNumber(10))).plus(((s)[(q).minus(_dafny.ONE)]).minus(new BigNumber(48)));
      }
    };
    static ParseBrace(s, j) {
      let _0_d1e = Regex.__default.DigitRun(s, (j).plus(_dafny.ONE));
      let _1_len1 = (_0_d1e).minus((j).plus(_dafny.ONE));
      if (((_1_len1).isLessThan(_dafny.ONE)) || ((new BigNumber(4)).isLessThan(_1_len1))) {
        return Regex.QR.create_QBad();
      } else {
        let _2_v1 = Regex.__default.DigitVal(s, (j).plus(_dafny.ONE), _0_d1e);
        if (((_0_d1e).isLessThan(new BigNumber((s).length))) && (((s)[_0_d1e]).isEqualTo(Regex.__default.RC))) {
          return Regex.QR.create_Q(_2_v1, _2_v1, (_0_d1e).plus(_dafny.ONE));
        } else if (((_0_d1e).isLessThan(new BigNumber((s).length))) && (((s)[_0_d1e]).isEqualTo(Regex.__default.COMMA))) {
          let _3_d2e = Regex.__default.DigitRun(s, (_0_d1e).plus(_dafny.ONE));
          let _4_len2 = (_3_d2e).minus((_0_d1e).plus(_dafny.ONE));
          if ((((new BigNumber(4)).isLessThan(_4_len2)) || ((new BigNumber((s).length)).isLessThanOrEqualTo(_3_d2e))) || (!((s)[_3_d2e]).isEqualTo(Regex.__default.RC))) {
            return Regex.QR.create_QBad();
          } else {
            let _5_mx = (((_4_len2).isEqualTo(_dafny.ZERO)) ? (new BigNumber(-1)) : (Regex.__default.DigitVal(s, (_0_d1e).plus(_dafny.ONE), _3_d2e)));
            if ((!(_5_mx).isEqualTo(new BigNumber(-1))) && ((_5_mx).isLessThan(_2_v1))) {
              return Regex.QR.create_QBad();
            } else {
              return Regex.QR.create_Q(_2_v1, _5_mx, (_3_d2e).plus(_dafny.ONE));
            }
          }
        } else {
          return Regex.QR.create_QBad();
        }
      }
    };
    static Single(code) {
      return Regex.Esc.create_Esc(Regex.Item.create_Rng(code, code), false, code);
    };
    static EscapeInner(s, i, inClass) {
      if ((new BigNumber((s).length)).isLessThanOrEqualTo((i).plus(_dafny.ONE))) {
        return Regex.PR.create_PRef();
      } else {
        let _0_c = (s)[(i).plus(_dafny.ONE)];
        let _1_j = (i).plus(new BigNumber(2));
        if ((_0_c).isEqualTo(new BigNumber(100))) {
          return Regex.PR.create_POk(Regex.Esc.create_Esc(Regex.Item.create_In(Regex.__default.DIGIT), true, new BigNumber(-1)), _1_j);
        } else if ((_0_c).isEqualTo(new BigNumber(68))) {
          return Regex.PR.create_POk(Regex.Esc.create_Esc(Regex.Item.create_NotIn(Regex.__default.DIGIT), true, new BigNumber(-1)), _1_j);
        } else if ((_0_c).isEqualTo(new BigNumber(119))) {
          return Regex.PR.create_POk(Regex.Esc.create_Esc(Regex.Item.create_In(Regex.__default.WORD), true, new BigNumber(-1)), _1_j);
        } else if ((_0_c).isEqualTo(new BigNumber(87))) {
          return Regex.PR.create_POk(Regex.Esc.create_Esc(Regex.Item.create_NotIn(Regex.__default.WORD), true, new BigNumber(-1)), _1_j);
        } else if ((_0_c).isEqualTo(new BigNumber(115))) {
          return Regex.PR.create_POk(Regex.Esc.create_Esc(Regex.Item.create_In(Regex.__default.SPACE), true, new BigNumber(-1)), _1_j);
        } else if ((_0_c).isEqualTo(new BigNumber(83))) {
          return Regex.PR.create_POk(Regex.Esc.create_Esc(Regex.Item.create_NotIn(Regex.__default.SPACE), true, new BigNumber(-1)), _1_j);
        } else if ((_0_c).isEqualTo(new BigNumber(116))) {
          return Regex.PR.create_POk(Regex.__default.Single(new BigNumber(9)), _1_j);
        } else if ((_0_c).isEqualTo(new BigNumber(110))) {
          return Regex.PR.create_POk(Regex.__default.Single(new BigNumber(10)), _1_j);
        } else if ((_0_c).isEqualTo(new BigNumber(118))) {
          return Regex.PR.create_POk(Regex.__default.Single(new BigNumber(11)), _1_j);
        } else if ((_0_c).isEqualTo(new BigNumber(102))) {
          return Regex.PR.create_POk(Regex.__default.Single(new BigNumber(12)), _1_j);
        } else if ((_0_c).isEqualTo(new BigNumber(114))) {
          return Regex.PR.create_POk(Regex.__default.Single(new BigNumber(13)), _1_j);
        } else if ((_0_c).isEqualTo(new BigNumber(48))) {
          if (((_1_j).isLessThan(new BigNumber((s).length))) && (Regex.__default.IsDigit((s)[_1_j]))) {
            return Regex.PR.create_PRef();
          } else {
            return Regex.PR.create_POk(Regex.__default.Single(_dafny.ZERO), _1_j);
          }
        } else if ((_0_c).isEqualTo(new BigNumber(120))) {
          if (((((_1_j).plus(new BigNumber(2))).isLessThanOrEqualTo(new BigNumber((s).length))) && (Regex.__default.IsHex((s)[_1_j]))) && (Regex.__default.IsHex((s)[(_1_j).plus(_dafny.ONE)]))) {
            return Regex.PR.create_POk(Regex.__default.Single(((Regex.__default.HexVal((s)[_1_j])).multipliedBy(new BigNumber(16))).plus(Regex.__default.HexVal((s)[(_1_j).plus(_dafny.ONE)]))), (_1_j).plus(new BigNumber(2)));
          } else {
            return Regex.PR.create_PRef();
          }
        } else if ((_0_c).isEqualTo(new BigNumber(117))) {
          if (((((((_1_j).plus(new BigNumber(4))).isLessThanOrEqualTo(new BigNumber((s).length))) && (Regex.__default.IsHex((s)[_1_j]))) && (Regex.__default.IsHex((s)[(_1_j).plus(_dafny.ONE)]))) && (Regex.__default.IsHex((s)[(_1_j).plus(new BigNumber(2))]))) && (Regex.__default.IsHex((s)[(_1_j).plus(new BigNumber(3))]))) {
            return Regex.PR.create_POk(Regex.__default.Single(((((((Regex.__default.HexVal((s)[_1_j])).multipliedBy(new BigNumber(16))).plus(Regex.__default.HexVal((s)[(_1_j).plus(_dafny.ONE)]))).multipliedBy(new BigNumber(16))).plus(Regex.__default.HexVal((s)[(_1_j).plus(new BigNumber(2))]))).multipliedBy(new BigNumber(16))).plus(Regex.__default.HexVal((s)[(_1_j).plus(new BigNumber(3))]))), (_1_j).plus(new BigNumber(4)));
          } else {
            return Regex.PR.create_PRef();
          }
        } else if ((_0_c).isEqualTo(new BigNumber(99))) {
          if (((_1_j).isLessThan(new BigNumber((s).length))) && (Regex.__default.IsAlpha((s)[_1_j]))) {
            return Regex.PR.create_POk(Regex.__default.Single(((s)[_1_j]).mod(new BigNumber(32))), (_1_j).plus(_dafny.ONE));
          } else {
            return Regex.PR.create_PRef();
          }
        } else if ((_0_c).isEqualTo(new BigNumber(98))) {
          if (inClass) {
            return Regex.PR.create_POk(Regex.__default.Single(new BigNumber(8)), _1_j);
          } else {
            return Regex.PR.create_PRef();
          }
        } else if ((Regex.__default.IsAlnum(_0_c)) || ((_0_c).isEqualTo(new BigNumber(95)))) {
          return Regex.PR.create_PRef();
        } else {
          return Regex.PR.create_POk(Regex.__default.Single(_0_c), _1_j);
        }
      }
    };
    static ReadAtom(s, i) {
      if ((new BigNumber((s).length)).isLessThanOrEqualTo(i)) {
        return Regex.PR.create_PRef();
      } else if (((s)[i]).isEqualTo(Regex.__default.BS)) {
        let _source0 = Regex.__default.EscapeInner(s, i, true);
        {
          if (_source0.is_PRef) {
            return Regex.PR.create_PRef();
          }
        }
        {
          let _0_e = (_source0).v;
          let _1_j = (_source0).i;
          return Regex.PR.create_POk(Regex.CAtom.create_CAtom((_0_e).dtor_item, (_0_e).dtor_ch, (_0_e).dtor_cls), _1_j);
        }
      } else {
        return Regex.PR.create_POk(Regex.CAtom.create_CAtom(Regex.Item.create_Rng((s)[i], (s)[i]), (s)[i], false), (i).plus(_dafny.ONE));
      }
    };
    static ParseClsBody(s, i) {
      if ((new BigNumber((s).length)).isLessThanOrEqualTo(i)) {
        return Regex.PR.create_PRef();
      } else if (((s)[i]).isEqualTo(Regex.__default.RB)) {
        return Regex.PR.create_POk(_dafny.Seq.of(), (i).plus(_dafny.ONE));
      } else {
        let _source0 = Regex.__default.ReadAtom(s, i);
        {
          if (_source0.is_PRef) {
            return Regex.PR.create_PRef();
          }
        }
        {
          let _0_a = (_source0).v;
          let _1_j = (_source0).i;
          if (((((_1_j).isLessThan(new BigNumber((s).length))) && (((s)[_1_j]).isEqualTo(Regex.__default.DASH))) && (((_1_j).plus(_dafny.ONE)).isLessThan(new BigNumber((s).length)))) && (!((s)[(_1_j).plus(_dafny.ONE)]).isEqualTo(Regex.__default.RB))) {
            let _source1 = Regex.__default.ReadAtom(s, (_1_j).plus(_dafny.ONE));
            {
              if (_source1.is_PRef) {
                return Regex.PR.create_PRef();
              }
            }
            {
              let _2_b = (_source1).v;
              let _3_k = (_source1).i;
              if (((_0_a).dtor_cls) || ((_2_b).dtor_cls)) {
                let _source2 = Regex.__default.ParseClsBody(s, _3_k);
                {
                  if (_source2.is_PRef) {
                    return Regex.PR.create_PRef();
                  }
                }
                {
                  let _4_rest = (_source2).v;
                  let _5_e = (_source2).i;
                  return Regex.PR.create_POk(_dafny.Seq.Concat(_dafny.Seq.of((_0_a).dtor_it, Regex.Item.create_Rng(Regex.__default.DASH, Regex.__default.DASH), (_2_b).dtor_it), _4_rest), _5_e);
                }
              } else if (((_2_b).dtor_ch).isLessThan((_0_a).dtor_ch)) {
                return Regex.PR.create_PRef();
              } else {
                let _source3 = Regex.__default.ParseClsBody(s, _3_k);
                {
                  if (_source3.is_PRef) {
                    return Regex.PR.create_PRef();
                  }
                }
                {
                  let _6_rest = (_source3).v;
                  let _7_e = (_source3).i;
                  return Regex.PR.create_POk(_dafny.Seq.Concat(_dafny.Seq.of(Regex.Item.create_Rng((_0_a).dtor_ch, (_2_b).dtor_ch)), _6_rest), _7_e);
                }
              }
            }
          } else {
            let _source4 = Regex.__default.ParseClsBody(s, _1_j);
            {
              if (_source4.is_PRef) {
                return Regex.PR.create_PRef();
              }
            }
            {
              let _8_rest = (_source4).v;
              let _9_e = (_source4).i;
              return Regex.PR.create_POk(_dafny.Seq.Concat(_dafny.Seq.of((_0_a).dtor_it), _8_rest), _9_e);
            }
          }
        }
      }
    };
    static ParseCls(s, i) {
      let _0_neg = (((i).plus(_dafny.ONE)).isLessThan(new BigNumber((s).length))) && (((s)[(i).plus(_dafny.ONE)]).isEqualTo(Regex.__default.CARET));
      let _1_st = ((_0_neg) ? ((i).plus(new BigNumber(2))) : ((i).plus(_dafny.ONE)));
      let _source0 = Regex.__default.ParseClsBody(s, _1_st);
      {
        if (_source0.is_PRef) {
          return Regex.PR.create_PRef();
        }
      }
      {
        let _2_items = (_source0).v;
        let _3_e = (_source0).i;
        return Regex.PR.create_POk(Regex.Node.create_Set(Regex.CharSet.create_Cls(_2_items, _0_neg)), _3_e);
      }
    };
    static IsQuantChar(c) {
      return ((((c).isEqualTo(Regex.__default.STAR)) || ((c).isEqualTo(Regex.__default.PLUS))) || ((c).isEqualTo(Regex.__default.QM))) || ((c).isEqualTo(Regex.__default.LC));
    };
    static ParseAlt(s, i) {
      let _source0 = Regex.__default.ParseCat(s, i);
      {
        if (_source0.is_PRef) {
          return Regex.PR.create_PRef();
        }
      }
      {
        let _0_first = (_source0).v;
        let _1_j = (_source0).i;
        let _source1 = Regex.__default.ParseAltTail(s, _1_j);
        {
          if (_source1.is_PRef) {
            return Regex.PR.create_PRef();
          }
        }
        {
          let _2_rest = (_source1).v;
          let _3_k = (_source1).i;
          return Regex.PR.create_POk((((_2_rest).is_Nil) ? (Regex.Node.create_Cat(_0_first)) : (Regex.Node.create_Alt(Regex.NList.create_Cons(Regex.Node.create_Cat(_0_first), _2_rest)))), _3_k);
        }
      }
    };
    static ParseAltTail(s, j) {
      if (((j).isLessThan(new BigNumber((s).length))) && (((s)[j]).isEqualTo(Regex.__default.BAR))) {
        let _source0 = Regex.__default.ParseCat(s, (j).plus(_dafny.ONE));
        {
          if (_source0.is_PRef) {
            return Regex.PR.create_PRef();
          }
        }
        {
          let _0_c = (_source0).v;
          let _1_k = (_source0).i;
          let _source1 = Regex.__default.ParseAltTail(s, _1_k);
          {
            if (_source1.is_PRef) {
              return Regex.PR.create_PRef();
            }
          }
          {
            let _2_rest = (_source1).v;
            let _3_e = (_source1).i;
            return Regex.PR.create_POk(Regex.NList.create_Cons(Regex.Node.create_Cat(_0_c), _2_rest), _3_e);
          }
        }
      } else {
        return Regex.PR.create_POk(Regex.NList.create_Nil(), j);
      }
    };
    static ParseCat(s, i) {
      if ((((new BigNumber((s).length)).isLessThanOrEqualTo(i)) || (((s)[i]).isEqualTo(Regex.__default.BAR))) || (((s)[i]).isEqualTo(Regex.__default.RP))) {
        return Regex.PR.create_POk(Regex.NList.create_Nil(), i);
      } else {
        let _source0 = Regex.__default.ParseQuantified(s, i);
        {
          if (_source0.is_PRef) {
            return Regex.PR.create_PRef();
          }
        }
        {
          let _0_q = (_source0).v;
          let _1_j = (_source0).i;
          let _source1 = Regex.__default.ParseCat(s, _1_j);
          {
            if (_source1.is_PRef) {
              return Regex.PR.create_PRef();
            }
          }
          {
            let _2_rest = (_source1).v;
            let _3_k = (_source1).i;
            return Regex.PR.create_POk(Regex.NList.create_Cons(_0_q, _2_rest), _3_k);
          }
        }
      }
    };
    static ParseQuantified(s, i) {
      let _source0 = Regex.__default.ParseAtom(s, i);
      {
        if (_source0.is_PRef) {
          return Regex.PR.create_PRef();
        }
      }
      {
        let _0_atom = (_source0).v;
        let _1_j = (_source0).i;
        let _2_q = (((new BigNumber((s).length)).isLessThanOrEqualTo(_1_j)) ? (Regex.QR.create_NoQ()) : (((((s)[_1_j]).isEqualTo(Regex.__default.STAR)) ? (Regex.QR.create_Q(_dafny.ZERO, new BigNumber(-1), (_1_j).plus(_dafny.ONE))) : (((((s)[_1_j]).isEqualTo(Regex.__default.PLUS)) ? (Regex.QR.create_Q(_dafny.ONE, new BigNumber(-1), (_1_j).plus(_dafny.ONE))) : (((((s)[_1_j]).isEqualTo(Regex.__default.QM)) ? (Regex.QR.create_Q(_dafny.ZERO, _dafny.ONE, (_1_j).plus(_dafny.ONE))) : (((((s)[_1_j]).isEqualTo(Regex.__default.LC)) ? (Regex.__default.ParseBrace(s, _1_j)) : (Regex.QR.create_NoQ()))))))))));
        let _source1 = _2_q;
        {
          if (_source1.is_NoQ) {
            return Regex.PR.create_POk(_0_atom, _1_j);
          }
        }
        {
          if (_source1.is_QBad) {
            return Regex.PR.create_PRef();
          }
        }
        {
          let _3_mn = (_source1).mn;
          let _4_mx = (_source1).mx;
          let _5_k = (_source1).k;
          if (((_0_atom).is_Bol) || ((_0_atom).is_Eol)) {
            return Regex.PR.create_PRef();
          } else if (((!(_4_mx).isEqualTo(new BigNumber(-1))) && ((Regex.__default.MAX__REPEAT).isLessThan(_4_mx))) || ((Regex.__default.MAX__REPEAT).isLessThan(_3_mn))) {
            return Regex.PR.create_PRef();
          } else {
            let _6_k2 = ((((_5_k).isLessThan(new BigNumber((s).length))) && (((s)[_5_k]).isEqualTo(Regex.__default.QM))) ? ((_5_k).plus(_dafny.ONE)) : (_5_k));
            if (((_6_k2).isLessThan(new BigNumber((s).length))) && (Regex.__default.IsQuantChar((s)[_6_k2]))) {
              return Regex.PR.create_PRef();
            } else {
              return Regex.PR.create_POk(Regex.Node.create_Rep(_0_atom, _3_mn, _4_mx), _6_k2);
            }
          }
        }
      }
    };
    static ParseAtom(s, i) {
      let _0_c = (s)[i];
      if ((_0_c).isEqualTo(Regex.__default.LP)) {
        let _1_i1 = (i).plus(_dafny.ONE);
        let _2_q = ((_1_i1).isLessThan(new BigNumber((s).length))) && (((s)[_1_i1]).isEqualTo(Regex.__default.QM));
        if ((_2_q) && (!((((_1_i1).plus(_dafny.ONE)).isLessThan(new BigNumber((s).length))) && (((s)[(_1_i1).plus(_dafny.ONE)]).isEqualTo(Regex.__default.COLON))))) {
          return Regex.PR.create_PRef();
        } else {
          let _3_i2 = ((_2_q) ? ((_1_i1).plus(new BigNumber(2))) : (_1_i1));
          let _source0 = Regex.__default.ParseAlt(s, _3_i2);
          {
            if (_source0.is_PRef) {
              return Regex.PR.create_PRef();
            }
          }
          {
            let _4_n = (_source0).v;
            let _5_k = (_source0).i;
            if (((_5_k).isLessThan(new BigNumber((s).length))) && (((s)[_5_k]).isEqualTo(Regex.__default.RP))) {
              return Regex.PR.create_POk(_4_n, (_5_k).plus(_dafny.ONE));
            } else {
              return Regex.PR.create_PRef();
            }
          }
        }
      } else if ((_0_c).isEqualTo(Regex.__default.LB)) {
        return Regex.__default.ParseCls(s, i);
      } else if ((_0_c).isEqualTo(Regex.__default.DOT)) {
        return Regex.PR.create_POk(Regex.Node.create_Set(Regex.CharSet.create_Cls(_dafny.Seq.of(Regex.Item.create_In(Regex.__default.LINE__TERMINATORS)), true)), (i).plus(_dafny.ONE));
      } else if ((_0_c).isEqualTo(Regex.__default.CARET)) {
        return Regex.PR.create_POk(Regex.Node.create_Bol(), (i).plus(_dafny.ONE));
      } else if ((_0_c).isEqualTo(Regex.__default.DOLLAR)) {
        return Regex.PR.create_POk(Regex.Node.create_Eol(), (i).plus(_dafny.ONE));
      } else if ((_0_c).isEqualTo(Regex.__default.BS)) {
        let _source1 = Regex.__default.EscapeInner(s, i, false);
        {
          if (_source1.is_PRef) {
            return Regex.PR.create_PRef();
          }
        }
        {
          let _6_e = (_source1).v;
          let _7_j = (_source1).i;
          return Regex.PR.create_POk(Regex.Node.create_Set(Regex.CharSet.create_Cls(_dafny.Seq.of((_6_e).dtor_item), false)), _7_j);
        }
      } else if ((((_0_c).isEqualTo(Regex.__default.STAR)) || ((_0_c).isEqualTo(Regex.__default.PLUS))) || ((_0_c).isEqualTo(Regex.__default.QM))) {
        return Regex.PR.create_PRef();
      } else if ((_0_c).isEqualTo(Regex.__default.LC)) {
        return Regex.PR.create_PRef();
      } else {
        return Regex.PR.create_POk(Regex.Node.create_Set(Regex.CharSet.create_Cls(_dafny.Seq.of(Regex.Item.create_Rng(_0_c, _0_c)), false)), (i).plus(_dafny.ONE));
      }
    };
    static Parse(s) {
      let _source0 = Regex.__default.ParseAlt(s, _dafny.ZERO);
      {
        if (_source0.is_PRef) {
          return Regex.Option.create_None();
        }
      }
      {
        let _0_n = (_source0).v;
        let _1_j = (_source0).i;
        if ((_1_j).isLessThan(new BigNumber((s).length))) {
          return Regex.Option.create_None();
        } else {
          return Regex.Option.create_Some(_0_n);
        }
      }
    };
    static Size(n) {
      let _source0 = n;
      {
        if (_source0.is_Set) {
          return _dafny.ONE;
        }
      }
      {
        if (_source0.is_Bol) {
          return _dafny.ONE;
        }
      }
      {
        if (_source0.is_Eol) {
          return _dafny.ONE;
        }
      }
      {
        if (_source0.is_Cat) {
          let _0_l = (_source0).cat;
          return Regex.__default.SizeL(_0_l);
        }
      }
      {
        if (_source0.is_Alt) {
          let _1_l = (_source0).alt;
          return Regex.__default.AltSize(_1_l);
        }
      }
      {
        let _2_inner = (_source0).inner;
        let _3_mn = (_source0).mn;
        let _4_mx = (_source0).mx;
        return ((_3_mn).multipliedBy(Regex.__default.Size(_2_inner))).plus((((_4_mx).isEqualTo(new BigNumber(-1))) ? ((Regex.__default.Size(_2_inner)).plus(new BigNumber(2))) : (((_4_mx).minus(_3_mn)).multipliedBy((Regex.__default.Size(_2_inner)).plus(_dafny.ONE)))));
      }
    };
    static SizeL(l) {
      let _source0 = l;
      {
        if (_source0.is_Nil) {
          return _dafny.ZERO;
        }
      }
      {
        let _0_h = (_source0).hd;
        let _1_t = (_source0).tl;
        return (Regex.__default.Size(_0_h)).plus(Regex.__default.SizeL(_1_t));
      }
    };
    static AltSize(l) {
      let _source0 = l;
      {
        if (_source0.is_Nil) {
          return _dafny.ZERO;
        }
      }
      {
        let _0_h = (_source0).hd;
        let _1_t = (_source0).tl;
        if ((_1_t).is_Nil) {
          return Regex.__default.Size(_0_h);
        } else {
          return ((Regex.__default.Size(_0_h)).plus(new BigNumber(2))).plus(Regex.__default.AltSize(_1_t));
        }
      }
    };
    static Emit(n, a) {
      let _source0 = n;
      {
        if (_source0.is_Set) {
          let _0_cs = (_source0).cs;
          return _dafny.Seq.of(Regex.Inst.create_ISet(_0_cs));
        }
      }
      {
        if (_source0.is_Bol) {
          return _dafny.Seq.of(Regex.Inst.create_IBol());
        }
      }
      {
        if (_source0.is_Eol) {
          return _dafny.Seq.of(Regex.Inst.create_IEol());
        }
      }
      {
        if (_source0.is_Cat) {
          let _1_l = (_source0).cat;
          return Regex.__default.EmitL(_1_l, a);
        }
      }
      {
        if (_source0.is_Alt) {
          let _2_l = (_source0).alt;
          return Regex.__default.EmitAlt(_2_l, a);
        }
      }
      {
        let _3_inner = (_source0).inner;
        let _4_mn = (_source0).mn;
        let _5_mx = (_source0).mx;
        let _6_S = Regex.__default.Size(_3_inner);
        let _7_L = (a).plus((_4_mn).multipliedBy(_6_S));
        return _dafny.Seq.Concat(Regex.__default.EmitCopies(_3_inner, a, _4_mn), (((_5_mx).isEqualTo(new BigNumber(-1))) ? (_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(Regex.Inst.create_ISplit((_7_L).plus(_dafny.ONE), ((_7_L).plus(_6_S)).plus(new BigNumber(2)))), Regex.__default.Emit(_3_inner, (_7_L).plus(_dafny.ONE))), _dafny.Seq.of(Regex.Inst.create_IJmp(_7_L)))) : (Regex.__default.EmitChain(_3_inner, _7_L, (_5_mx).minus(_4_mn), (_7_L).plus(((_5_mx).minus(_4_mn)).multipliedBy((_6_S).plus(_dafny.ONE)))))));
      }
    };
    static EmitL(l, a) {
      let _source0 = l;
      {
        if (_source0.is_Nil) {
          return _dafny.Seq.of();
        }
      }
      {
        let _0_h = (_source0).hd;
        let _1_t = (_source0).tl;
        return _dafny.Seq.Concat(Regex.__default.Emit(_0_h, a), Regex.__default.EmitL(_1_t, (a).plus(Regex.__default.Size(_0_h))));
      }
    };
    static EmitAlt(l, a) {
      let _source0 = l;
      {
        if (_source0.is_Nil) {
          return _dafny.Seq.of();
        }
      }
      {
        let _0_h = (_source0).hd;
        let _1_t = (_source0).tl;
        if ((_1_t).is_Nil) {
          return Regex.__default.Emit(_0_h, a);
        } else {
          return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(Regex.Inst.create_ISplit((a).plus(_dafny.ONE), ((a).plus(Regex.__default.Size(_0_h))).plus(new BigNumber(2)))), Regex.__default.Emit(_0_h, (a).plus(_dafny.ONE))), _dafny.Seq.of(Regex.Inst.create_IJmp((a).plus(Regex.__default.AltSize(l))))), Regex.__default.EmitAlt(_1_t, ((a).plus(Regex.__default.Size(_0_h))).plus(new BigNumber(2))));
        }
      }
    };
    static EmitCopies(inner, a, t) {
      if ((t).isEqualTo(_dafny.ZERO)) {
        return _dafny.Seq.of();
      } else {
        return _dafny.Seq.Concat(Regex.__default.Emit(inner, a), Regex.__default.EmitCopies(inner, (a).plus(Regex.__default.Size(inner)), (t).minus(_dafny.ONE)));
      }
    };
    static EmitChain(inner, L, u, end) {
      if ((u).isEqualTo(_dafny.ZERO)) {
        return _dafny.Seq.of();
      } else {
        return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(Regex.Inst.create_ISplit((L).plus(_dafny.ONE), end)), Regex.__default.Emit(inner, (L).plus(_dafny.ONE))), Regex.__default.EmitChain(inner, ((L).plus(_dafny.ONE)).plus(Regex.__default.Size(inner)), (u).minus(_dafny.ONE), end));
      }
    };
    static Compile(ast) {
      if ((Regex.__default.MAX__NFA__INSTRUCTIONS).isLessThan((Regex.__default.Size(ast)).plus(_dafny.ONE))) {
        return Regex.Option.create_None();
      } else {
        return Regex.Option.create_Some(_dafny.Seq.Concat(Regex.__default.Emit(ast, _dafny.ZERO), _dafny.Seq.of(Regex.Inst.create_IMatch())));
      }
    };
    static CompileSrc(src) {
      let _source0 = Regex.__default.Parse(src);
      {
        if (_source0.is_None) {
          return Regex.Option.create_None();
        }
      }
      {
        let _0_ast = (_source0).v;
        return Regex.__default.Compile(_0_ast);
      }
    };
    static InstTargetsIn(ins, pc, lo, hi) {
      let _source0 = ins;
      {
        if (_source0.is_ISet) {
          return ((lo).isLessThanOrEqualTo((pc).plus(_dafny.ONE))) && (((pc).plus(_dafny.ONE)).isLessThanOrEqualTo(hi));
        }
      }
      {
        if (_source0.is_ISplit) {
          let _0_x = (_source0).x;
          let _1_y = (_source0).y;
          return (((lo).isLessThanOrEqualTo(_0_x)) && ((_0_x).isLessThanOrEqualTo(hi))) && (((lo).isLessThanOrEqualTo(_1_y)) && ((_1_y).isLessThanOrEqualTo(hi)));
        }
      }
      {
        if (_source0.is_IJmp) {
          let _2_x = (_source0).x;
          return ((lo).isLessThanOrEqualTo(_2_x)) && ((_2_x).isLessThanOrEqualTo(hi));
        }
      }
      {
        if (_source0.is_IBol) {
          return ((lo).isLessThanOrEqualTo((pc).plus(_dafny.ONE))) && (((pc).plus(_dafny.ONE)).isLessThanOrEqualTo(hi));
        }
      }
      {
        if (_source0.is_IEol) {
          return ((lo).isLessThanOrEqualTo((pc).plus(_dafny.ONE))) && (((pc).plus(_dafny.ONE)).isLessThanOrEqualTo(hi));
        }
      }
      {
        return false;
      }
    };
    static TargetsIn(e, a, lo, hi) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((e).length)), true, function (_forall_var_0) {
        let _0_k = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_k)) && ((_0_k).isLessThan(new BigNumber((e).length)))) || (Regex.__default.InstTargetsIn((e)[_0_k], (a).plus(_0_k), lo, hi));
      });
    };
    static ClosedW(P, a, b) {
      return (((_dafny.ZERO).isLessThanOrEqualTo(a)) && ((b).isLessThanOrEqualTo(new BigNumber((P).length)))) && (_dafny.Quantifier(_dafny.IntegerRange(a, b), true, function (_forall_var_0) {
        let _0_pc = _forall_var_0;
        return !(((a).isLessThanOrEqualTo(_0_pc)) && ((_0_pc).isLessThan(b))) || (Regex.__default.InstTargetsIn((P)[_0_pc], _0_pc, a, b));
      }));
    };
    static Embedded(P, e, a) {
      return (((_dafny.ZERO).isLessThanOrEqualTo(a)) && (((a).plus(new BigNumber((e).length))).isLessThanOrEqualTo(new BigNumber((P).length)))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((e).length)), true, function (_forall_var_0) {
        let _0_k = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_k)) && ((_0_k).isLessThan(new BigNumber((e).length)))) || (_dafny.areEqual((P)[(a).plus(_0_k)], (e)[_0_k]));
      }));
    };
    static WFProg(P) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((P).length)), true, function (_forall_var_0) {
        let _0_pc = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_pc)) && ((_0_pc).isLessThan(new BigNumber((P).length)))) || ((((P)[_0_pc]).is_IMatch) || (Regex.__default.InstTargetsIn((P)[_0_pc], _0_pc, _dafny.ZERO, (new BigNumber((P).length)).minus(_dafny.ONE))));
      });
    };
    static HandledEscapeChar(c) {
      return (_dafny.Set.fromElements(new BigNumber(100), new BigNumber(68), new BigNumber(119), new BigNumber(87), new BigNumber(115), new BigNumber(83), new BigNumber(116), new BigNumber(110), new BigNumber(118), new BigNumber(102), new BigNumber(114), new BigNumber(48), new BigNumber(120), new BigNumber(117), new BigNumber(99), new BigNumber(98))).contains(c);
    };
    static Add(P, s, pos, pc0, visited, list, cn0, stack, matched0) {
      let cn = _dafny.ZERO;
      let matched = false;
      let steps = _dafny.ZERO;
      cn = cn0;
      matched = matched0;
      steps = _dafny.ZERO;
      let _0_sp;
      _0_sp = _dafny.ONE;
      (stack)[(_dafny.ZERO)] = pc0;
      let _1_np;
      _1_np = new BigNumber((P).length);
      while ((_dafny.ZERO).isLessThan(_0_sp)) {
        _0_sp = (_0_sp).minus(_dafny.ONE);
        let _2_pc;
        _2_pc = (stack)[_0_sp];
        steps = (steps).plus(_dafny.ONE);
        if (!((visited)[_2_pc])) {
          (visited)[(_2_pc)] = true;
          let _source0 = (P)[_2_pc];
          Lmatch0: {
            {
              if (_source0.is_ISet) {
                let _3_cs = (_source0).cs;
                (list)[(cn)] = _2_pc;
                cn = (cn).plus(_dafny.ONE);
                break Lmatch0;
              }
            }
            {
              if (_source0.is_ISplit) {
                let _4_x = (_source0).x;
                let _5_y = (_source0).y;
                (stack)[(_0_sp)] = _5_y;
                let _index0 = (_0_sp).plus(_dafny.ONE);
                (stack)[_index0] = _4_x;
                _0_sp = (_0_sp).plus(new BigNumber(2));
                break Lmatch0;
              }
            }
            {
              if (_source0.is_IJmp) {
                let _6_x = (_source0).x;
                (stack)[(_0_sp)] = _6_x;
                _0_sp = (_0_sp).plus(_dafny.ONE);
                break Lmatch0;
              }
            }
            {
              if (_source0.is_IBol) {
                if ((pos).isEqualTo(_dafny.ZERO)) {
                  (stack)[(_0_sp)] = (_2_pc).plus(_dafny.ONE);
                  _0_sp = (_0_sp).plus(_dafny.ONE);
                }
                break Lmatch0;
              }
            }
            {
              if (_source0.is_IEol) {
                if ((pos).isEqualTo(new BigNumber((s).length))) {
                  (stack)[(_0_sp)] = (_2_pc).plus(_dafny.ONE);
                  _0_sp = (_0_sp).plus(_dafny.ONE);
                }
                break Lmatch0;
              }
            }
            {
              if ((pos).isEqualTo(new BigNumber((s).length))) {
                matched = true;
              }
            }
          }
        } else {
        }
      }
      return [cn, matched, steps];
    }
    static sp1(spOld) {
      return (spOld).minus(_dafny.ONE);
    };
    static Phase(P, s, pos, seeds, ns) {
      let list = [];
      let cn = _dafny.ZERO;
      let matched = false;
      let work = _dafny.ZERO;
      let _0_np;
      _0_np = new BigNumber((P).length);
      let _1_visited;
      let _init0 = function (_2___v8) {
        return false;
      };
      let _nw0 = Array((_0_np).toNumber());
      for (let _i0_0 = 0; _i0_0 < new BigNumber(_nw0.length); _i0_0++) {
        _nw0[_i0_0] = _init0(new BigNumber(_i0_0));
      }
      _1_visited = _nw0;
      let _nw1 = Array((_0_np).toNumber()).fill(_dafny.ZERO);
      list = _nw1;
      let _3_stack;
      let _nw2 = Array((((new BigNumber(2)).multipliedBy(_0_np)).plus(new BigNumber(2))).toNumber()).fill(_dafny.ZERO);
      _3_stack = _nw2;
      cn = _dafny.ZERO;
      matched = false;
      work = _0_np;
      let _4_j;
      _4_j = _dafny.ZERO;
      while ((_4_j).isLessThan(ns)) {
        let _5_c2;
        let _6_m2;
        let _7_st;
        let _out0;
        let _out1;
        let _out2;
        let _outcollector0 = Regex.__default.Add(P, s, pos, (seeds)[_4_j], _1_visited, list, cn, _3_stack, matched);
        _out0 = _outcollector0[0];
        _out1 = _outcollector0[1];
        _out2 = _outcollector0[2];
        _5_c2 = _out0;
        _6_m2 = _out1;
        _7_st = _out2;
        cn = _5_c2;
        matched = _6_m2;
        work = (work).plus(_7_st);
        _4_j = (_4_j).plus(_dafny.ONE);
      }
      return [list, cn, matched, work];
    }
    static Advance(P, s, pos, list, cn) {
      let sarr = [];
      let ns = _dafny.ZERO;
      let _0_np;
      _0_np = new BigNumber((P).length);
      let _nw0 = Array((_0_np).toNumber()).fill(_dafny.ZERO);
      sarr = _nw0;
      ns = _dafny.ZERO;
      let _1_k;
      _1_k = _dafny.ZERO;
      while ((_1_k).isLessThan(cn)) {
        let _2_pc;
        _2_pc = (list)[_1_k];
        if (Regex.__default.SetHas(((P)[_2_pc]).dtor_cs, (s)[pos])) {
          (sarr)[(ns)] = (_2_pc).plus(_dafny.ONE);
          ns = (ns).plus(_dafny.ONE);
        }
        _1_k = (_1_k).plus(_dafny.ONE);
      }
      return [sarr, ns];
    }
    static Run(P, s) {
      let r = Regex.Option.Default();
      let work = _dafny.ZERO;
      let _0_np;
      _0_np = new BigNumber((P).length);
      let _1_n;
      _1_n = new BigNumber((s).length);
      if ((Regex.__default.MAX__MATCH__STEPS).isLessThan((_0_np).multipliedBy((_1_n).plus(_dafny.ONE)))) {
        let _rhs0 = Regex.Option.create_None();
        let _rhs1 = _dafny.ZERO;
        r = _rhs0;
        work = _rhs1;
        return [r, work];
      }
      let _2_seeds0;
      let _nw0 = Array((_dafny.ONE).toNumber()).fill(_dafny.ZERO);
      _2_seeds0 = _nw0;
      (_2_seeds0)[(_dafny.ZERO)] = _dafny.ZERO;
      let _3_list;
      let _4_cn;
      let _5_matched;
      let _6_w;
      let _out0;
      let _out1;
      let _out2;
      let _out3;
      let _outcollector0 = Regex.__default.Phase(P, s, _dafny.ZERO, _2_seeds0, _dafny.ONE);
      _out0 = _outcollector0[0];
      _out1 = _outcollector0[1];
      _out2 = _outcollector0[2];
      _out3 = _outcollector0[3];
      _3_list = _out0;
      _4_cn = _out1;
      _5_matched = _out2;
      _6_w = _out3;
      work = (_6_w).plus(_dafny.ONE);
      let _7_K;
      _7_K = (new BigNumber(6)).multipliedBy(_0_np);
      let _8_pos;
      _8_pos = _dafny.ZERO;
      while ((_8_pos).isLessThan(_1_n)) {
        let _9_sarr;
        let _10_ns;
        let _out4;
        let _out5;
        let _outcollector1 = Regex.__default.Advance(P, s, _8_pos, _3_list, _4_cn);
        _out4 = _outcollector1[0];
        _out5 = _outcollector1[1];
        _9_sarr = _out4;
        _10_ns = _out5;
        let _11_l2;
        let _12_c2;
        let _13_m2;
        let _14_w2;
        let _out6;
        let _out7;
        let _out8;
        let _out9;
        let _outcollector2 = Regex.__default.Phase(P, s, (_8_pos).plus(_dafny.ONE), _9_sarr, _10_ns);
        _out6 = _outcollector2[0];
        _out7 = _outcollector2[1];
        _out8 = _outcollector2[2];
        _out9 = _outcollector2[3];
        _11_l2 = _out6;
        _12_c2 = _out7;
        _13_m2 = _out8;
        _14_w2 = _out9;
        work = (((work).plus(_0_np)).plus(_4_cn)).plus(_14_w2);
        _3_list = _11_l2;
        _4_cn = _12_c2;
        _5_matched = _13_m2;
        _8_pos = (_8_pos).plus(_dafny.ONE);
      }
      r = Regex.Option.create_Some(_5_matched);
      return [r, work];
    }
    static CeilLog2(n) {
      let _0___accumulator = _dafny.ZERO;
      TAIL_CALL_START: while (true) {
        if ((n).isLessThanOrEqualTo(_dafny.ONE)) {
          return (_dafny.ZERO).plus(_0___accumulator);
        } else {
          _0___accumulator = (_0___accumulator).plus(_dafny.ONE);
          let _in0 = _dafny.EuclideanDivision((n).plus(_dafny.ONE), new BigNumber(2));
          n = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static GuardBrace(s, i) {
      let _0_d1e = Regex.__default.DigitRun(s, (i).plus(_dafny.ONE));
      if ((_0_d1e).isEqualTo((i).plus(_dafny.ONE))) {
        return Regex.GB.create_GBad();
      } else {
        let _1_lo = Regex.__default.DigitVal(s, (i).plus(_dafny.ONE), _0_d1e);
        if (((_0_d1e).isLessThan(new BigNumber((s).length))) && (((s)[_0_d1e]).isEqualTo(Regex.__default.RC))) {
          return Regex.GB.create_GQ(_1_lo, _1_lo, ((_0_d1e).plus(_dafny.ONE)).minus(i));
        } else if (((_0_d1e).isLessThan(new BigNumber((s).length))) && (((s)[_0_d1e]).isEqualTo(Regex.__default.COMMA))) {
          let _2_d2e = Regex.__default.DigitRun(s, (_0_d1e).plus(_dafny.ONE));
          if (((_2_d2e).isLessThan(new BigNumber((s).length))) && (((s)[_2_d2e]).isEqualTo(Regex.__default.RC))) {
            if ((_2_d2e).isEqualTo((_0_d1e).plus(_dafny.ONE))) {
              return Regex.GB.create_GQ(_1_lo, new BigNumber(-1), ((_2_d2e).plus(_dafny.ONE)).minus(i));
            } else {
              return Regex.GB.create_GQ(_1_lo, Regex.__default.DigitVal(s, (_0_d1e).plus(_dafny.ONE), _2_d2e), ((_2_d2e).plus(_dafny.ONE)).minus(i));
            }
          } else {
            return Regex.GB.create_GBad();
          }
        } else {
          return Regex.GB.create_GBad();
        }
      }
    };
    static ClassEnd(s, j) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((s).length)).isLessThanOrEqualTo(j)) {
          return new BigNumber(-1);
        } else if (((s)[j]).isEqualTo(Regex.__default.RB)) {
          return j;
        } else if (((s)[j]).isEqualTo(Regex.__default.BS)) {
          let _in0 = s;
          let _in1 = (j).plus(new BigNumber(2));
          s = _in0;
          j = _in1;
          continue TAIL_CALL_START;
        } else {
          let _in2 = s;
          let _in3 = (j).plus(_dafny.ONE);
          s = _in2;
          j = _in3;
          continue TAIL_CALL_START;
        }
      }
    };
    static GuardGo(s, i, prev, unb, bits, st) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((s).length)).isLessThanOrEqualTo(i)) {
          return ((new BigNumber((st).length)).isEqualTo(_dafny.ONE)) && ((Regex.__default.CompileSrc(s)).is_Some);
        } else {
          let _0_ch = (s)[i];
          if ((_0_ch).isEqualTo(Regex.__default.BS)) {
            if ((new BigNumber((s).length)).isLessThanOrEqualTo((i).plus(_dafny.ONE))) {
              return false;
            } else if ((((new BigNumber(49)).isLessThanOrEqualTo((s)[(i).plus(_dafny.ONE)])) && (((s)[(i).plus(_dafny.ONE)]).isLessThanOrEqualTo(new BigNumber(57)))) || (((s)[(i).plus(_dafny.ONE)]).isEqualTo(new BigNumber(107)))) {
              return false;
            } else {
              let _in0 = s;
              let _in1 = (i).plus(new BigNumber(2));
              let _in2 = Regex.Prev.create_PAtom();
              let _in3 = unb;
              let _in4 = bits;
              let _in5 = st;
              s = _in0;
              i = _in1;
              prev = _in2;
              unb = _in3;
              bits = _in4;
              st = _in5;
              continue TAIL_CALL_START;
            }
          } else if ((_0_ch).isEqualTo(Regex.__default.LB)) {
            let _1_j0 = (((((i).plus(_dafny.ONE)).isLessThan(new BigNumber((s).length))) && (((s)[(i).plus(_dafny.ONE)]).isEqualTo(Regex.__default.CARET))) ? ((i).plus(new BigNumber(2))) : ((i).plus(_dafny.ONE)));
            let _2_e = Regex.__default.ClassEnd(s, _1_j0);
            if ((_2_e).isLessThan(_dafny.ZERO)) {
              return false;
            } else {
              let _in6 = s;
              let _in7 = (_2_e).plus(_dafny.ONE);
              let _in8 = Regex.Prev.create_PAtom();
              let _in9 = unb;
              let _in10 = bits;
              let _in11 = st;
              s = _in6;
              i = _in7;
              prev = _in8;
              unb = _in9;
              bits = _in10;
              st = _in11;
              continue TAIL_CALL_START;
            }
          } else if ((_0_ch).isEqualTo(Regex.__default.LP)) {
            let _3_nx = (((((i).plus(_dafny.ONE)).isLessThan(new BigNumber((s).length))) && (((s)[(i).plus(_dafny.ONE)]).isEqualTo(Regex.__default.QM))) ? ((((((i).plus(new BigNumber(2))).isLessThan(new BigNumber((s).length))) && (((s)[(i).plus(new BigNumber(2))]).isEqualTo(Regex.__default.COLON))) ? ((i).plus(new BigNumber(3))) : (new BigNumber(-1)))) : ((i).plus(_dafny.ONE)));
            if ((_3_nx).isLessThan(_dafny.ZERO)) {
              return false;
            } else {
              let _in12 = s;
              let _in13 = _3_nx;
              let _in14 = Regex.Prev.create_PNone();
              let _in15 = unb;
              let _in16 = bits;
              let _in17 = _dafny.Seq.Concat(st, _dafny.Seq.of(Regex.Fr.create_Fr(false, false)));
              s = _in12;
              i = _in13;
              prev = _in14;
              unb = _in15;
              bits = _in16;
              st = _in17;
              continue TAIL_CALL_START;
            }
          } else if ((_0_ch).isEqualTo(Regex.__default.RP)) {
            if ((new BigNumber((st).length)).isLessThan(new BigNumber(2))) {
              return false;
            } else {
              let _4_f = (st)[(new BigNumber((st).length)).minus(_dafny.ONE)];
              let _5_par = (st)[(new BigNumber((st).length)).minus(new BigNumber(2))];
              let _in18 = s;
              let _in19 = (i).plus(_dafny.ONE);
              let _in20 = Regex.Prev.create_PFrame((_4_f).dtor_q, (_4_f).dtor_a);
              let _in21 = unb;
              let _in22 = bits;
              let _in23 = _dafny.Seq.Concat((st).slice(0, (new BigNumber((st).length)).minus(new BigNumber(2))), _dafny.Seq.of(Regex.Fr.create_Fr(((_5_par).dtor_q) || ((_4_f).dtor_q), ((_5_par).dtor_a) || ((_4_f).dtor_a))));
              s = _in18;
              i = _in19;
              prev = _in20;
              unb = _in21;
              bits = _in22;
              st = _in23;
              continue TAIL_CALL_START;
            }
          } else if ((_0_ch).isEqualTo(Regex.__default.BAR)) {
            if ((Regex.__default.MAX__REGEX__COST__BITS).isLessThan((bits).plus(_dafny.ONE))) {
              return false;
            } else {
              let _in24 = s;
              let _in25 = (i).plus(_dafny.ONE);
              let _in26 = Regex.Prev.create_PNone();
              let _in27 = unb;
              let _in28 = (bits).plus(_dafny.ONE);
              let _in29 = _dafny.Seq.Concat((st).slice(0, (new BigNumber((st).length)).minus(_dafny.ONE)), _dafny.Seq.of(Regex.Fr.create_Fr(((st)[(new BigNumber((st).length)).minus(_dafny.ONE)]).dtor_q, true)));
              s = _in24;
              i = _in25;
              prev = _in26;
              unb = _in27;
              bits = _in28;
              st = _in29;
              continue TAIL_CALL_START;
            }
          } else if (((((_0_ch).isEqualTo(Regex.__default.STAR)) || ((_0_ch).isEqualTo(Regex.__default.PLUS))) || ((_0_ch).isEqualTo(Regex.__default.QM))) || ((_0_ch).isEqualTo(Regex.__default.LC))) {
            let _6_q = ((((_0_ch).isEqualTo(Regex.__default.STAR)) || ((_0_ch).isEqualTo(Regex.__default.PLUS))) ? (Regex.GB.create_GQ(_dafny.ZERO, new BigNumber(-1), _dafny.ONE)) : ((((_0_ch).isEqualTo(Regex.__default.QM)) ? (Regex.GB.create_GQ(_dafny.ZERO, _dafny.ONE, _dafny.ONE)) : (Regex.__default.GuardBrace(s, i)))));
            if ((_6_q).is_GBad) {
              return false;
            } else if ((((_0_ch).isEqualTo(Regex.__default.LC)) && (!((_6_q).dtor_hi).isEqualTo(new BigNumber(-1)))) && (((_6_q).dtor_hi).isLessThan((_6_q).dtor_lo))) {
              return false;
            } else if ((prev).is_PNone) {
              return false;
            } else if (((prev).is_PFrame) && (((prev).dtor_q) || ((prev).dtor_a))) {
              return false;
            } else {
              let _7_unbounded = ((_6_q).dtor_hi).isEqualTo(new BigNumber(-1));
              if ((_7_unbounded) && ((Regex.__default.MAX__UNBOUNDED__QUANTIFIERS).isLessThan((unb).plus(_dafny.ONE)))) {
                return false;
              } else if ((!(_7_unbounded)) && ((Regex.__default.MAX__BOUNDED__REPEAT).isLessThan((_6_q).dtor_hi))) {
                return false;
              } else {
                let _8_add = ((_7_unbounded) ? (Regex.__default.UNBOUNDED__QUANTIFIER__BITS) : ((((_dafny.ONE).isLessThan((((_6_q).dtor_hi).minus((_6_q).dtor_lo)).plus(_dafny.ONE))) ? (Regex.__default.CeilLog2((((_6_q).dtor_hi).minus((_6_q).dtor_lo)).plus(_dafny.ONE))) : (_dafny.ZERO))));
                if ((Regex.__default.MAX__REGEX__COST__BITS).isLessThan((bits).plus(_8_add))) {
                  return false;
                } else {
                  let _9_i2 = (i).plus((_6_q).dtor_len);
                  let _10_i3 = ((((_9_i2).isLessThan(new BigNumber((s).length))) && (((s)[_9_i2]).isEqualTo(Regex.__default.QM))) ? ((_9_i2).plus(_dafny.ONE)) : (_9_i2));
                  let _in30 = s;
                  let _in31 = _10_i3;
                  let _in32 = Regex.Prev.create_PNone();
                  let _in33 = ((_7_unbounded) ? ((unb).plus(_dafny.ONE)) : (unb));
                  let _in34 = (bits).plus(_8_add);
                  let _in35 = _dafny.Seq.Concat((st).slice(0, (new BigNumber((st).length)).minus(_dafny.ONE)), _dafny.Seq.of(Regex.Fr.create_Fr(true, ((st)[(new BigNumber((st).length)).minus(_dafny.ONE)]).dtor_a)));
                  s = _in30;
                  i = _in31;
                  prev = _in32;
                  unb = _in33;
                  bits = _in34;
                  st = _in35;
                  continue TAIL_CALL_START;
                }
              }
            }
          } else {
            let _in36 = s;
            let _in37 = (i).plus(_dafny.ONE);
            let _in38 = Regex.Prev.create_PAtom();
            let _in39 = unb;
            let _in40 = bits;
            let _in41 = st;
            s = _in36;
            i = _in37;
            prev = _in38;
            unb = _in39;
            bits = _in40;
            st = _in41;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static IsSafeSource(s) {
      return Regex.__default.GuardGo(s, _dafny.ZERO, Regex.Prev.create_PNone(), _dafny.ZERO, _dafny.ZERO, _dafny.Seq.of(Regex.Fr.create_Fr(false, false)));
    };
    static FullMatch(src, subj) {
      let r = Regex.Option.Default();
      let _source0 = Regex.__default.Parse(src);
      Lmatch0: {
        {
          if (_source0.is_None) {
            r = Regex.Option.create_None();
            return r;
            break Lmatch0;
          }
        }
        {
          let _0_ast = (_source0).v;
          let _source1 = Regex.__default.Compile(_0_ast);
          Lmatch1: {
            {
              if (_source1.is_None) {
                r = Regex.Option.create_None();
                return r;
                break Lmatch1;
              }
            }
            {
              let _1_P = (_source1).v;
              let _2_rr;
              let _3_work;
              let _out0;
              let _out1;
              let _outcollector0 = Regex.__default.Run(_1_P, subj);
              _out0 = _outcollector0[0];
              _out1 = _outcollector0[1];
              _2_rr = _out0;
              _3_work = _out1;
              r = _2_rr;
            }
          }
        }
      }
      return r;
    }
    static Compiles(src) {
      let b = false;
      b = (Regex.__default.CompileSrc(src)).is_Some;
      return b;
    }
    static SafeSource(src) {
      let b = false;
      b = Regex.__default.IsSafeSource(src);
      return b;
    }
    static ReMatches(src, subj) {
      let b = false;
      if (((Regex.__default.MAX__RE__SRC__LEN).isLessThan(new BigNumber((src).length))) || ((Regex.__default.MAX__RE__RESOURCE__LEN).isLessThan(new BigNumber((subj).length)))) {
        b = false;
        return b;
      }
      if (!(Regex.__default.IsSafeSource(src))) {
        b = false;
        return b;
      }
      let _0_r;
      let _out0;
      _out0 = Regex.__default.FullMatch(src, subj);
      _0_r = _out0;
      b = _dafny.areEqual(_0_r, Regex.Option.create_Some(true));
      return b;
    }
    static get DIGIT() {
      return _dafny.Seq.of(_dafny.Tuple.of(new BigNumber(48), new BigNumber(57)));
    };
    static get WORD() {
      return _dafny.Seq.of(_dafny.Tuple.of(new BigNumber(48), new BigNumber(57)), _dafny.Tuple.of(new BigNumber(65), new BigNumber(90)), _dafny.Tuple.of(new BigNumber(95), new BigNumber(95)), _dafny.Tuple.of(new BigNumber(97), new BigNumber(122)));
    };
    static get SPACE() {
      return _dafny.Seq.of(_dafny.Tuple.of(new BigNumber(9), new BigNumber(13)), _dafny.Tuple.of(new BigNumber(32), new BigNumber(32)), _dafny.Tuple.of(new BigNumber(160), new BigNumber(160)), _dafny.Tuple.of(new BigNumber(5760), new BigNumber(5760)), _dafny.Tuple.of(new BigNumber(8192), new BigNumber(8202)), _dafny.Tuple.of(new BigNumber(8232), new BigNumber(8233)), _dafny.Tuple.of(new BigNumber(8239), new BigNumber(8239)), _dafny.Tuple.of(new BigNumber(8287), new BigNumber(8287)), _dafny.Tuple.of(new BigNumber(12288), new BigNumber(12288)), _dafny.Tuple.of(new BigNumber(65279), new BigNumber(65279)));
    };
    static get LINE__TERMINATORS() {
      return _dafny.Seq.of(_dafny.Tuple.of(new BigNumber(10), new BigNumber(10)), _dafny.Tuple.of(new BigNumber(13), new BigNumber(13)), _dafny.Tuple.of(new BigNumber(8232), new BigNumber(8233)));
    };
    static get LC() {
      return new BigNumber(123);
    };
    static get RC() {
      return new BigNumber(125);
    };
    static get COMMA() {
      return new BigNumber(44);
    };
    static get BS() {
      return new BigNumber(92);
    };
    static get RB() {
      return new BigNumber(93);
    };
    static get DASH() {
      return new BigNumber(45);
    };
    static get LB() {
      return new BigNumber(91);
    };
    static get CARET() {
      return new BigNumber(94);
    };
    static get STAR() {
      return new BigNumber(42);
    };
    static get PLUS() {
      return new BigNumber(43);
    };
    static get QM() {
      return new BigNumber(63);
    };
    static get BAR() {
      return new BigNumber(124);
    };
    static get RP() {
      return new BigNumber(41);
    };
    static get LP() {
      return new BigNumber(40);
    };
    static get COLON() {
      return new BigNumber(58);
    };
    static get DOT() {
      return new BigNumber(46);
    };
    static get DOLLAR() {
      return new BigNumber(36);
    };
    static get MAX__REPEAT() {
      return new BigNumber(64);
    };
    static get MAX__NFA__INSTRUCTIONS() {
      return new BigNumber(4096);
    };
    static get MAX__MATCH__STEPS() {
      return new BigNumber(2000000);
    };
    static get MAX__UNBOUNDED__QUANTIFIERS() {
      return new BigNumber(3);
    };
    static get MAX__REGEX__COST__BITS() {
      return new BigNumber(22);
    };
    static get MAX__BOUNDED__REPEAT() {
      return new BigNumber(64);
    };
    static get UNBOUNDED__QUANTIFIER__BITS() {
      return new BigNumber(8);
    };
    static get MAX__RE__SRC__LEN() {
      return new BigNumber(200);
    };
    static get MAX__RE__RESOURCE__LEN() {
      return new BigNumber(512);
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
        return "Regex.Option.None";
      } else if (this.$tag === 1) {
        return "Regex.Option.Some" + "(" + _dafny.toString(this.v) + ")";
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
      return Regex.Option.create_None();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Option.Default();
        }
      };
    }
  }

  $module.Item = class Item {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Rng(lo, hi) {
      let $dt = new Item(0);
      $dt.lo = lo;
      $dt.hi = hi;
      return $dt;
    }
    static create_In(rs) {
      let $dt = new Item(1);
      $dt.rs = rs;
      return $dt;
    }
    static create_NotIn(rs) {
      let $dt = new Item(2);
      $dt.rs = rs;
      return $dt;
    }
    get is_Rng() { return this.$tag === 0; }
    get is_In() { return this.$tag === 1; }
    get is_NotIn() { return this.$tag === 2; }
    get dtor_lo() { return this.lo; }
    get dtor_hi() { return this.hi; }
    get dtor_rs() { return this.rs; }
    toString() {
      if (this.$tag === 0) {
        return "Regex.Item.Rng" + "(" + _dafny.toString(this.lo) + ", " + _dafny.toString(this.hi) + ")";
      } else if (this.$tag === 1) {
        return "Regex.Item.In" + "(" + _dafny.toString(this.rs) + ")";
      } else if (this.$tag === 2) {
        return "Regex.Item.NotIn" + "(" + _dafny.toString(this.rs) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.lo, other.lo) && _dafny.areEqual(this.hi, other.hi);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.rs, other.rs);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.rs, other.rs);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Regex.Item.create_Rng(_dafny.ZERO, _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Item.Default();
        }
      };
    }
  }

  $module.CharSet = class CharSet {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Cls(items, neg) {
      let $dt = new CharSet(0);
      $dt.items = items;
      $dt.neg = neg;
      return $dt;
    }
    get is_Cls() { return this.$tag === 0; }
    get dtor_items() { return this.items; }
    get dtor_neg() { return this.neg; }
    toString() {
      if (this.$tag === 0) {
        return "Regex.CharSet.Cls" + "(" + _dafny.toString(this.items) + ", " + _dafny.toString(this.neg) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.items, other.items) && this.neg === other.neg;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Regex.CharSet.create_Cls(_dafny.Seq.of(), false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return CharSet.Default();
        }
      };
    }
  }

  $module.Node = class Node {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Set(cs) {
      let $dt = new Node(0);
      $dt.cs = cs;
      return $dt;
    }
    static create_Bol() {
      let $dt = new Node(1);
      return $dt;
    }
    static create_Eol() {
      let $dt = new Node(2);
      return $dt;
    }
    static create_Cat(cat) {
      let $dt = new Node(3);
      $dt.cat = cat;
      return $dt;
    }
    static create_Alt(alt) {
      let $dt = new Node(4);
      $dt.alt = alt;
      return $dt;
    }
    static create_Rep(inner, mn, mx) {
      let $dt = new Node(5);
      $dt.inner = inner;
      $dt.mn = mn;
      $dt.mx = mx;
      return $dt;
    }
    get is_Set() { return this.$tag === 0; }
    get is_Bol() { return this.$tag === 1; }
    get is_Eol() { return this.$tag === 2; }
    get is_Cat() { return this.$tag === 3; }
    get is_Alt() { return this.$tag === 4; }
    get is_Rep() { return this.$tag === 5; }
    get dtor_cs() { return this.cs; }
    get dtor_cat() { return this.cat; }
    get dtor_alt() { return this.alt; }
    get dtor_inner() { return this.inner; }
    get dtor_mn() { return this.mn; }
    get dtor_mx() { return this.mx; }
    toString() {
      if (this.$tag === 0) {
        return "Regex.Node.Set" + "(" + _dafny.toString(this.cs) + ")";
      } else if (this.$tag === 1) {
        return "Regex.Node.Bol";
      } else if (this.$tag === 2) {
        return "Regex.Node.Eol";
      } else if (this.$tag === 3) {
        return "Regex.Node.Cat" + "(" + _dafny.toString(this.cat) + ")";
      } else if (this.$tag === 4) {
        return "Regex.Node.Alt" + "(" + _dafny.toString(this.alt) + ")";
      } else if (this.$tag === 5) {
        return "Regex.Node.Rep" + "(" + _dafny.toString(this.inner) + ", " + _dafny.toString(this.mn) + ", " + _dafny.toString(this.mx) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.cs, other.cs);
      } else if (this.$tag === 1) {
        return other.$tag === 1;
      } else if (this.$tag === 2) {
        return other.$tag === 2;
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.cat, other.cat);
      } else if (this.$tag === 4) {
        return other.$tag === 4 && _dafny.areEqual(this.alt, other.alt);
      } else if (this.$tag === 5) {
        return other.$tag === 5 && _dafny.areEqual(this.inner, other.inner) && _dafny.areEqual(this.mn, other.mn) && _dafny.areEqual(this.mx, other.mx);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Regex.Node.create_Set(Regex.CharSet.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Node.Default();
        }
      };
    }
  }

  $module.NList = class NList {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Nil() {
      let $dt = new NList(0);
      return $dt;
    }
    static create_Cons(hd, tl) {
      let $dt = new NList(1);
      $dt.hd = hd;
      $dt.tl = tl;
      return $dt;
    }
    get is_Nil() { return this.$tag === 0; }
    get is_Cons() { return this.$tag === 1; }
    get dtor_hd() { return this.hd; }
    get dtor_tl() { return this.tl; }
    toString() {
      if (this.$tag === 0) {
        return "Regex.NList.Nil";
      } else if (this.$tag === 1) {
        return "Regex.NList.Cons" + "(" + _dafny.toString(this.hd) + ", " + _dafny.toString(this.tl) + ")";
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
        return other.$tag === 1 && _dafny.areEqual(this.hd, other.hd) && _dafny.areEqual(this.tl, other.tl);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Regex.NList.create_Nil();
    }
    static Rtd() {
      return class {
        static get Default() {
          return NList.Default();
        }
      };
    }
  }

  $module.PR = class PR {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_POk(v, i) {
      let $dt = new PR(0);
      $dt.v = v;
      $dt.i = i;
      return $dt;
    }
    static create_PRef() {
      let $dt = new PR(1);
      return $dt;
    }
    get is_POk() { return this.$tag === 0; }
    get is_PRef() { return this.$tag === 1; }
    get dtor_v() { return this.v; }
    get dtor_i() { return this.i; }
    toString() {
      if (this.$tag === 0) {
        return "Regex.PR.POk" + "(" + _dafny.toString(this.v) + ", " + _dafny.toString(this.i) + ")";
      } else if (this.$tag === 1) {
        return "Regex.PR.PRef";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.v, other.v) && _dafny.areEqual(this.i, other.i);
      } else if (this.$tag === 1) {
        return other.$tag === 1;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Regex.PR.create_PRef();
    }
    static Rtd() {
      return class {
        static get Default() {
          return PR.Default();
        }
      };
    }
  }

  $module.QR = class QR {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_NoQ() {
      let $dt = new QR(0);
      return $dt;
    }
    static create_Q(mn, mx, k) {
      let $dt = new QR(1);
      $dt.mn = mn;
      $dt.mx = mx;
      $dt.k = k;
      return $dt;
    }
    static create_QBad() {
      let $dt = new QR(2);
      return $dt;
    }
    get is_NoQ() { return this.$tag === 0; }
    get is_Q() { return this.$tag === 1; }
    get is_QBad() { return this.$tag === 2; }
    get dtor_mn() { return this.mn; }
    get dtor_mx() { return this.mx; }
    get dtor_k() { return this.k; }
    toString() {
      if (this.$tag === 0) {
        return "Regex.QR.NoQ";
      } else if (this.$tag === 1) {
        return "Regex.QR.Q" + "(" + _dafny.toString(this.mn) + ", " + _dafny.toString(this.mx) + ", " + _dafny.toString(this.k) + ")";
      } else if (this.$tag === 2) {
        return "Regex.QR.QBad";
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
        return other.$tag === 1 && _dafny.areEqual(this.mn, other.mn) && _dafny.areEqual(this.mx, other.mx) && _dafny.areEqual(this.k, other.k);
      } else if (this.$tag === 2) {
        return other.$tag === 2;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Regex.QR.create_NoQ();
    }
    static Rtd() {
      return class {
        static get Default() {
          return QR.Default();
        }
      };
    }
  }

  $module.Esc = class Esc {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Esc(item, cls, ch) {
      let $dt = new Esc(0);
      $dt.item = item;
      $dt.cls = cls;
      $dt.ch = ch;
      return $dt;
    }
    get is_Esc() { return this.$tag === 0; }
    get dtor_item() { return this.item; }
    get dtor_cls() { return this.cls; }
    get dtor_ch() { return this.ch; }
    toString() {
      if (this.$tag === 0) {
        return "Regex.Esc.Esc" + "(" + _dafny.toString(this.item) + ", " + _dafny.toString(this.cls) + ", " + _dafny.toString(this.ch) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.item, other.item) && this.cls === other.cls && _dafny.areEqual(this.ch, other.ch);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Regex.Esc.create_Esc(Regex.Item.Default(), false, _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Esc.Default();
        }
      };
    }
  }

  $module.CAtom = class CAtom {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_CAtom(it, ch, cls) {
      let $dt = new CAtom(0);
      $dt.it = it;
      $dt.ch = ch;
      $dt.cls = cls;
      return $dt;
    }
    get is_CAtom() { return this.$tag === 0; }
    get dtor_it() { return this.it; }
    get dtor_ch() { return this.ch; }
    get dtor_cls() { return this.cls; }
    toString() {
      if (this.$tag === 0) {
        return "Regex.CAtom.CAtom" + "(" + _dafny.toString(this.it) + ", " + _dafny.toString(this.ch) + ", " + _dafny.toString(this.cls) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.it, other.it) && _dafny.areEqual(this.ch, other.ch) && this.cls === other.cls;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Regex.CAtom.create_CAtom(Regex.Item.Default(), _dafny.ZERO, false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return CAtom.Default();
        }
      };
    }
  }

  $module.Inst = class Inst {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_ISet(cs) {
      let $dt = new Inst(0);
      $dt.cs = cs;
      return $dt;
    }
    static create_ISplit(x, y) {
      let $dt = new Inst(1);
      $dt.x = x;
      $dt.y = y;
      return $dt;
    }
    static create_IJmp(x) {
      let $dt = new Inst(2);
      $dt.x = x;
      return $dt;
    }
    static create_IBol() {
      let $dt = new Inst(3);
      return $dt;
    }
    static create_IEol() {
      let $dt = new Inst(4);
      return $dt;
    }
    static create_IMatch() {
      let $dt = new Inst(5);
      return $dt;
    }
    get is_ISet() { return this.$tag === 0; }
    get is_ISplit() { return this.$tag === 1; }
    get is_IJmp() { return this.$tag === 2; }
    get is_IBol() { return this.$tag === 3; }
    get is_IEol() { return this.$tag === 4; }
    get is_IMatch() { return this.$tag === 5; }
    get dtor_cs() { return this.cs; }
    get dtor_x() { return this.x; }
    get dtor_y() { return this.y; }
    toString() {
      if (this.$tag === 0) {
        return "Regex.Inst.ISet" + "(" + _dafny.toString(this.cs) + ")";
      } else if (this.$tag === 1) {
        return "Regex.Inst.ISplit" + "(" + _dafny.toString(this.x) + ", " + _dafny.toString(this.y) + ")";
      } else if (this.$tag === 2) {
        return "Regex.Inst.IJmp" + "(" + _dafny.toString(this.x) + ")";
      } else if (this.$tag === 3) {
        return "Regex.Inst.IBol";
      } else if (this.$tag === 4) {
        return "Regex.Inst.IEol";
      } else if (this.$tag === 5) {
        return "Regex.Inst.IMatch";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.cs, other.cs);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.x, other.x) && _dafny.areEqual(this.y, other.y);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.x, other.x);
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else if (this.$tag === 4) {
        return other.$tag === 4;
      } else if (this.$tag === 5) {
        return other.$tag === 5;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Regex.Inst.create_ISet(Regex.CharSet.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Inst.Default();
        }
      };
    }
  }

  $module.Fr = class Fr {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Fr(q, a) {
      let $dt = new Fr(0);
      $dt.q = q;
      $dt.a = a;
      return $dt;
    }
    get is_Fr() { return this.$tag === 0; }
    get dtor_q() { return this.q; }
    get dtor_a() { return this.a; }
    toString() {
      if (this.$tag === 0) {
        return "Regex.Fr.Fr" + "(" + _dafny.toString(this.q) + ", " + _dafny.toString(this.a) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.q === other.q && this.a === other.a;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Regex.Fr.create_Fr(false, false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Fr.Default();
        }
      };
    }
  }

  $module.Prev = class Prev {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_PNone() {
      let $dt = new Prev(0);
      return $dt;
    }
    static create_PAtom() {
      let $dt = new Prev(1);
      return $dt;
    }
    static create_PFrame(q, a) {
      let $dt = new Prev(2);
      $dt.q = q;
      $dt.a = a;
      return $dt;
    }
    get is_PNone() { return this.$tag === 0; }
    get is_PAtom() { return this.$tag === 1; }
    get is_PFrame() { return this.$tag === 2; }
    get dtor_q() { return this.q; }
    get dtor_a() { return this.a; }
    toString() {
      if (this.$tag === 0) {
        return "Regex.Prev.PNone";
      } else if (this.$tag === 1) {
        return "Regex.Prev.PAtom";
      } else if (this.$tag === 2) {
        return "Regex.Prev.PFrame" + "(" + _dafny.toString(this.q) + ", " + _dafny.toString(this.a) + ")";
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
        return other.$tag === 2 && this.q === other.q && this.a === other.a;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Regex.Prev.create_PNone();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Prev.Default();
        }
      };
    }
  }

  $module.GB = class GB {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_GBad() {
      let $dt = new GB(0);
      return $dt;
    }
    static create_GQ(lo, hi, len) {
      let $dt = new GB(1);
      $dt.lo = lo;
      $dt.hi = hi;
      $dt.len = len;
      return $dt;
    }
    get is_GBad() { return this.$tag === 0; }
    get is_GQ() { return this.$tag === 1; }
    get dtor_lo() { return this.lo; }
    get dtor_hi() { return this.hi; }
    get dtor_len() { return this.len; }
    toString() {
      if (this.$tag === 0) {
        return "Regex.GB.GBad";
      } else if (this.$tag === 1) {
        return "Regex.GB.GQ" + "(" + _dafny.toString(this.lo) + ", " + _dafny.toString(this.hi) + ", " + _dafny.toString(this.len) + ")";
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
        return other.$tag === 1 && _dafny.areEqual(this.lo, other.lo) && _dafny.areEqual(this.hi, other.hi) && _dafny.areEqual(this.len, other.len);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Regex.GB.create_GBad();
    }
    static Rtd() {
      return class {
        static get Default() {
          return GB.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module Regex
let _module = (function() {
  let $module = {};

  return $module;
})(); // end of module _module

// ---- exports (appended by formal/dafny/build-ext.sh) ----
module.exports = { _dafny, Regex };
