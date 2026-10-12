// Dafny program PolicyVm.dfy compiled into JavaScript
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
let PolicyVm = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "PolicyVm._default";
    }
    _parentTraits() {
      return [];
    }
    static S(s) {
      return _dafny.Seq.Create(new BigNumber((s).length), ((_0_s) => function (_1_i) {
        return ((((new BigNumber(((_0_s)[_1_i]).value)).isLessThan(new BigNumber(65536))) ? (new BigNumber(((_0_s)[_1_i]).value)) : (_dafny.ZERO))).toNumber();
      })(s));
    };
    static Has(es, k) {
      return ((_dafny.ZERO).isLessThan(new BigNumber((es).length))) && ((_dafny.areEqual(((es)[_dafny.ZERO]).dtor_k, k)) || (PolicyVm.__default.Has((es).slice(_dafny.ONE), k)));
    };
    static Get(es, k) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((es).length)).isEqualTo(_dafny.ZERO)) {
          return PolicyVm.Value.create_VUndef();
        } else if (_dafny.areEqual(((es)[_dafny.ZERO]).dtor_k, k)) {
          return ((es)[_dafny.ZERO]).dtor_v;
        } else {
          let _in0 = (es).slice(_dafny.ONE);
          let _in1 = k;
          es = _in0;
          k = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static Field(v, k) {
      let _source0 = v;
      {
        if (_source0.is_VObj) {
          let _0_es = (_source0).es;
          return PolicyVm.__default.Get(_0_es, k);
        }
      }
      {
        return PolicyVm.Value.create_VUndef();
      }
    };
    static IsObjRec(v) {
      return (v).is_VObj;
    };
    static IsObjLike(v) {
      return ((v).is_VObj) || ((v).is_VArr);
    };
    static NotT(t) {
      let _source0 = t;
      {
        if (_source0.is_TT) {
          return PolicyVm.Tri.create_TF();
        }
      }
      {
        if (_source0.is_TF) {
          return PolicyVm.Tri.create_TT();
        }
      }
      {
        return PolicyVm.Tri.create_TU();
      }
    };
    static AllT(ts) {
      if (_dafny.Seq.contains(ts, PolicyVm.Tri.create_TF())) {
        return PolicyVm.Tri.create_TF();
      } else if (_dafny.Seq.contains(ts, PolicyVm.Tri.create_TU())) {
        return PolicyVm.Tri.create_TU();
      } else {
        return PolicyVm.Tri.create_TT();
      }
    };
    static AnyT(ts) {
      if (_dafny.Seq.contains(ts, PolicyVm.Tri.create_TT())) {
        return PolicyVm.Tri.create_TT();
      } else if (_dafny.Seq.contains(ts, PolicyVm.Tri.create_TU())) {
        return PolicyVm.Tri.create_TU();
      } else {
        return PolicyVm.Tri.create_TF();
      }
    };
    static Refines(a, b) {
      return (_dafny.areEqual(a, PolicyVm.Tri.create_TU())) || (_dafny.areEqual(a, b));
    };
    static SplitDot(s) {
      return PolicyVm.__default.SplitAcc(s, _dafny.Seq.of(), _dafny.Seq.of());
    };
    static SplitAcc(s, cur, acc) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((s).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(acc, _dafny.Seq.of(cur));
        } else if (((s)[_dafny.ZERO]) === (46)) {
          let _in0 = (s).slice(_dafny.ONE);
          let _in1 = _dafny.Seq.of();
          let _in2 = _dafny.Seq.Concat(acc, _dafny.Seq.of(cur));
          s = _in0;
          cur = _in1;
          acc = _in2;
          continue TAIL_CALL_START;
        } else {
          let _in3 = (s).slice(_dafny.ONE);
          let _in4 = _dafny.Seq.Concat(cur, _dafny.Seq.of((s)[_dafny.ZERO]));
          let _in5 = acc;
          s = _in3;
          cur = _in4;
          acc = _in5;
          continue TAIL_CALL_START;
        }
      }
    };
    static IsRoot(s) {
      return ((_dafny.areEqual(s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("action")))) || (_dafny.areEqual(s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("subject"))))) || (_dafny.areEqual(s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("env"))));
    };
    static Forbidden(s) {
      return ((_dafny.areEqual(s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("__proto__")))) || (_dafny.areEqual(s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("constructor"))))) || (_dafny.areEqual(s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("prototype"))));
    };
    static IsDigit(u) {
      return ((48) <= (u)) && ((u) <= (57));
    };
    static AllDigits(s) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((s).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((s).length)))) || (PolicyVm.__default.IsDigit((s)[_0_i]));
      });
    };
    static IsIndex(s) {
      return (_dafny.areEqual(s, _dafny.Seq.of(48))) || (((((_dafny.ZERO).isLessThan(new BigNumber((s).length))) && ((49) <= ((s)[_dafny.ZERO]))) && (((s)[_dafny.ZERO]) <= (57))) && (PolicyVm.__default.AllDigits(s)));
    };
    static DigitsVal(s) {
      let _hresult = _dafny.ZERO;
      let _0_n;
      _0_n = _dafny.ZERO;
      let _1_i;
      _1_i = _dafny.ZERO;
      while ((_1_i).isLessThan(new BigNumber((s).length))) {
        _0_n = ((_0_n).multipliedBy(new BigNumber(10))).plus((new BigNumber((s)[_1_i])).minus(new BigNumber(48)));
        _1_i = (_1_i).plus(_dafny.ONE);
      }
      _hresult = _0_n;
      return _hresult;
      return _hresult;
    }
    static Walk(cur, segs, i) {
      TAIL_CALL_START: while (true) {
        if ((i).isEqualTo(new BigNumber((segs).length))) {
          return PolicyVm.Res.create_Res(true, cur);
        } else {
          let _0_s = (segs)[i];
          if ((PolicyVm.__default.Forbidden(_0_s)) || (!(PolicyVm.__default.IsObjLike(cur)))) {
            return PolicyVm.__default.NotFound;
          } else {
            let _source0 = cur;
            {
              if (_source0.is_VArr) {
                let _1_xs = (_source0).xs;
                if (!(PolicyVm.__default.IsIndex(_0_s))) {
                  return PolicyVm.__default.NotFound;
                } else {
                  let _2_idx = PolicyVm.__default.DigitsVal(_0_s);
                  if ((new BigNumber((_1_xs).length)).isLessThanOrEqualTo(_2_idx)) {
                    return PolicyVm.__default.NotFound;
                  } else if (((_1_xs)[_2_idx]).is_VUndef) {
                    return PolicyVm.__default.NotFound;
                  } else {
                    let _in0 = (_1_xs)[_2_idx];
                    let _in1 = segs;
                    let _in2 = (i).plus(_dafny.ONE);
                    cur = _in0;
                    segs = _in1;
                    i = _in2;
                    continue TAIL_CALL_START;
                  }
                }
              }
            }
            {
              let _3_es = (_source0).es;
              if (!(PolicyVm.__default.Has(_3_es, _0_s))) {
                return PolicyVm.__default.NotFound;
              } else {
                let _4_nx = PolicyVm.__default.Get(_3_es, _0_s);
                if ((_4_nx).is_VUndef) {
                  return PolicyVm.__default.NotFound;
                } else {
                  let _in3 = _4_nx;
                  let _in4 = segs;
                  let _in5 = (i).plus(_dafny.ONE);
                  cur = _in3;
                  segs = _in4;
                  i = _in5;
                  continue TAIL_CALL_START;
                }
              }
            }
          }
        }
      }
    };
    static ResolvePath(ctx, path) {
      if ((!((path).is_VStr)) || ((new BigNumber(((path).dtor_s).length)).isEqualTo(_dafny.ZERO))) {
        return PolicyVm.__default.NotFound;
      } else {
        let _0_segs = PolicyVm.__default.SplitDot((path).dtor_s);
        if (!(PolicyVm.__default.IsRoot((_0_segs)[_dafny.ZERO]))) {
          return PolicyVm.__default.NotFound;
        } else {
          let _1_cur = PolicyVm.__default.Field(ctx, (_0_segs)[_dafny.ZERO]);
          if ((_1_cur).is_VUndef) {
            return PolicyVm.__default.NotFound;
          } else {
            return PolicyVm.__default.Walk(_1_cur, _0_segs, _dafny.ONE);
          }
        }
      }
    };
    static IsHigh(u) {
      return ((55296) <= (u)) && ((u) <= (56319));
    };
    static IsLow(u) {
      return ((56320) <= (u)) && ((u) <= (57343));
    };
    static LoneAt(s, i) {
      return ((PolicyVm.__default.IsHigh((s)[i])) && (!((((i).plus(_dafny.ONE)).isLessThan(new BigNumber((s).length))) && (PolicyVm.__default.IsLow((s)[(i).plus(_dafny.ONE)]))))) || ((PolicyVm.__default.IsLow((s)[i])) && (!(((_dafny.ZERO).isLessThan(i)) && (PolicyVm.__default.IsHigh((s)[(i).minus(_dafny.ONE)])))));
    };
    static HasLone(s) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((s).length)), false, function (_exists_var_0) {
        let _0_i = _exists_var_0;
        return (((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((s).length)))) && (PolicyVm.__default.LoneAt(s, _0_i));
      });
    };
    static Enc(cp) {
      if ((cp).isLessThan(new BigNumber(128))) {
        return _dafny.Seq.of(cp);
      } else if ((cp).isLessThan(new BigNumber(2048))) {
        return _dafny.Seq.of((new BigNumber(192)).plus(_dafny.EuclideanDivision(cp, new BigNumber(64))), (new BigNumber(128)).plus((cp).mod(new BigNumber(64))));
      } else if ((cp).isLessThan(new BigNumber(65536))) {
        return _dafny.Seq.of((new BigNumber(224)).plus(_dafny.EuclideanDivision(cp, new BigNumber(4096))), (new BigNumber(128)).plus((_dafny.EuclideanDivision(cp, new BigNumber(64))).mod(new BigNumber(64))), (new BigNumber(128)).plus((cp).mod(new BigNumber(64))));
      } else {
        return _dafny.Seq.of((new BigNumber(240)).plus(_dafny.EuclideanDivision(cp, new BigNumber(262144))), (new BigNumber(128)).plus((_dafny.EuclideanDivision(cp, new BigNumber(4096))).mod(new BigNumber(64))), (new BigNumber(128)).plus((_dafny.EuclideanDivision(cp, new BigNumber(64))).mod(new BigNumber(64))), (new BigNumber(128)).plus((cp).mod(new BigNumber(64))));
      }
    };
    static Utf8(s) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((s).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          let _1_u = new BigNumber((s)[_dafny.ZERO]);
          if (((PolicyVm.__default.IsHigh((s)[_dafny.ZERO])) && ((_dafny.ONE).isLessThan(new BigNumber((s).length)))) && (PolicyVm.__default.IsLow((s)[_dafny.ONE]))) {
            _0___accumulator = _dafny.Seq.Concat(_0___accumulator, PolicyVm.__default.Enc(((new BigNumber(65536)).plus(((_1_u).minus(new BigNumber(55296))).multipliedBy(new BigNumber(1024)))).plus((new BigNumber((s)[_dafny.ONE])).minus(new BigNumber(56320)))));
            let _in0 = (s).slice(new BigNumber(2));
            s = _in0;
            continue TAIL_CALL_START;
          } else if ((PolicyVm.__default.IsHigh((s)[_dafny.ZERO])) || (PolicyVm.__default.IsLow((s)[_dafny.ZERO]))) {
            _0___accumulator = _dafny.Seq.Concat(_0___accumulator, PolicyVm.__default.Enc(new BigNumber(65533)));
            let _in1 = (s).slice(_dafny.ONE);
            s = _in1;
            continue TAIL_CALL_START;
          } else {
            _0___accumulator = _dafny.Seq.Concat(_0___accumulator, PolicyVm.__default.Enc(_1_u));
            let _in2 = (s).slice(_dafny.ONE);
            s = _in2;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static CmpBytes(a, b) {
      TAIL_CALL_START: while (true) {
        if (((new BigNumber((a).length)).isEqualTo(_dafny.ZERO)) && ((new BigNumber((b).length)).isEqualTo(_dafny.ZERO))) {
          return _dafny.ZERO;
        } else if ((new BigNumber((a).length)).isEqualTo(_dafny.ZERO)) {
          return new BigNumber(-1);
        } else if ((new BigNumber((b).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.ONE;
        } else if (((a)[_dafny.ZERO]).isLessThan((b)[_dafny.ZERO])) {
          return new BigNumber(-1);
        } else if (((b)[_dafny.ZERO]).isLessThan((a)[_dafny.ZERO])) {
          return _dafny.ONE;
        } else {
          let _in0 = (a).slice(_dafny.ONE);
          let _in1 = (b).slice(_dafny.ONE);
          a = _in0;
          b = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static Units(s) {
      return _dafny.Seq.Create(new BigNumber((s).length), ((_0_s) => function (_1_i) {
        return new BigNumber((_0_s)[_1_i]);
      })(s));
    };
    static CmpStr(a, b) {
      if (_dafny.areEqual(a, b)) {
        return _dafny.ZERO;
      } else {
        let _0_c = PolicyVm.__default.CmpBytes(PolicyVm.__default.Utf8(a), PolicyVm.__default.Utf8(b));
        if (!(_0_c).isEqualTo(_dafny.ZERO)) {
          return _0_c;
        } else {
          return PolicyVm.__default.CmpBytes(PolicyVm.__default.Units(a), PolicyVm.__default.Units(b));
        }
      }
    };
    static CanonL(xs) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((xs).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((xs).length)))) || (PolicyVm.__default.Canon((xs)[_0_i]));
      });
    };
    static CanonE(es) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((es).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((es).length)))) || (PolicyVm.__default.Canon(((es)[_0_i]).dtor_v));
      });
    };
    static Canon(v) {
      let _source0 = v;
      {
        if (_source0.is_VNull) {
          return true;
        }
      }
      {
        if (_source0.is_VBool) {
          return true;
        }
      }
      {
        if (_source0.is_VNum) {
          return true;
        }
      }
      {
        if (_source0.is_VStr) {
          return true;
        }
      }
      {
        if (_source0.is_VArr) {
          let _0_xs = (_source0).xs;
          return PolicyVm.__default.CanonL(_0_xs);
        }
      }
      {
        if (_source0.is_VObj) {
          let _1_es = (_source0).es;
          let _2_plain = (_source0).plain;
          return (_2_plain) && (PolicyVm.__default.CanonE(_1_es));
        }
      }
      {
        return false;
      }
    };
    static SzV(v) {
      let _source0 = v;
      {
        if (_source0.is_VArr) {
          let _0_xs = (_source0).xs;
          return (_dafny.ONE).plus(PolicyVm.__default.SzL(_0_xs));
        }
      }
      {
        if (_source0.is_VObj) {
          let _1_es = (_source0).es;
          return (_dafny.ONE).plus(PolicyVm.__default.SzE(_1_es));
        }
      }
      {
        return _dafny.ONE;
      }
    };
    static SzL(xs) {
      if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.ZERO;
      } else {
        return (PolicyVm.__default.SzV((xs)[_dafny.ZERO])).plus(PolicyVm.__default.SzL((xs).slice(_dafny.ONE)));
      }
    };
    static SzE(es) {
      if ((new BigNumber((es).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.ZERO;
      } else {
        return ((PolicyVm.__default.SzV(((es)[_dafny.ZERO]).dtor_v)).plus(_dafny.ONE)).plus(PolicyVm.__default.SzE((es).slice(_dafny.ONE)));
      }
    };
    static InsertE(e, sorted) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((sorted).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(e));
        } else if ((_dafny.ZERO).isLessThanOrEqualTo(PolicyVm.__default.CmpStr(((sorted)[_dafny.ZERO]).dtor_k, (e).dtor_k))) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.Concat(_dafny.Seq.of(e), sorted));
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of((sorted)[_dafny.ZERO]));
          let _in0 = e;
          let _in1 = (sorted).slice(_dafny.ONE);
          e = _in0;
          sorted = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static SortE(es) {
      if ((new BigNumber((es).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Seq.of();
      } else {
        return PolicyVm.__default.InsertE((es)[_dafny.ZERO], PolicyVm.__default.SortE((es).slice(_dafny.ONE)));
      }
    };
    static SerL(xs) {
      if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Seq.of();
      } else {
        return _dafny.Seq.Concat(PolicyVm.__default.Ser((xs)[_dafny.ZERO]), (((new BigNumber((xs).length)).isEqualTo(_dafny.ONE)) ? (_dafny.Seq.of()) : (_dafny.Seq.Concat(_dafny.Seq.of(PolicyVm.Tok.create_TComma()), PolicyVm.__default.SerL((xs).slice(_dafny.ONE))))));
      }
    };
    static SerE(es) {
      if ((new BigNumber((es).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Seq.of();
      } else {
        return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(PolicyVm.Tok.create_TStrT(((es)[_dafny.ZERO]).dtor_k), PolicyVm.Tok.create_TColon()), PolicyVm.__default.Ser(((es)[_dafny.ZERO]).dtor_v)), (((new BigNumber((es).length)).isEqualTo(_dafny.ONE)) ? (_dafny.Seq.of()) : (_dafny.Seq.Concat(_dafny.Seq.of(PolicyVm.Tok.create_TComma()), PolicyVm.__default.SerE((es).slice(_dafny.ONE))))));
      }
    };
    static Ser(v) {
      let _source0 = v;
      {
        if (_source0.is_VNull) {
          return _dafny.Seq.of(PolicyVm.Tok.create_TNullT());
        }
      }
      {
        if (_source0.is_VBool) {
          let _0_b = (_source0).b;
          return _dafny.Seq.of(((_0_b) ? (PolicyVm.Tok.create_TTrueT()) : (PolicyVm.Tok.create_TFalseT())));
        }
      }
      {
        if (_source0.is_VNum) {
          let _1_r = (_source0).r;
          return _dafny.Seq.of(PolicyVm.Tok.create_TNumT(_1_r));
        }
      }
      {
        if (_source0.is_VStr) {
          let _2_s = (_source0).s;
          return _dafny.Seq.of(PolicyVm.Tok.create_TStrT(_2_s));
        }
      }
      {
        if (_source0.is_VArr) {
          let _3_xs = (_source0).xs;
          return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(PolicyVm.Tok.create_TOpenA()), PolicyVm.__default.SerL(_3_xs)), _dafny.Seq.of(PolicyVm.Tok.create_TCloseA()));
        }
      }
      {
        let _4_es = (_source0).es;
        return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(PolicyVm.Tok.create_TOpenO()), PolicyVm.__default.SerE(PolicyVm.__default.SortE(_4_es))), _dafny.Seq.of(PolicyVm.Tok.create_TCloseO()));
      }
    };
    static DeepEq(a, b) {
      return ((PolicyVm.__default.Canon(a)) && (PolicyVm.__default.Canon(b))) && (_dafny.areEqual(PolicyVm.__default.Ser(a), PolicyVm.__default.Ser(b)));
    };
    static Ordered(a, b) {
      if (((a).is_VNum) && ((b).is_VNum)) {
        return PolicyVm.Option.create_Some(((((a).dtor_r).isLessThan((b).dtor_r)) ? (new BigNumber(-1)) : (((((b).dtor_r).isLessThan((a).dtor_r)) ? (_dafny.ONE) : (_dafny.ZERO)))));
      } else if (((a).is_VStr) && ((b).is_VStr)) {
        if ((PolicyVm.__default.HasLone((a).dtor_s)) || (PolicyVm.__default.HasLone((b).dtor_s))) {
          return PolicyVm.Option.create_None();
        } else {
          return PolicyVm.Option.create_Some(PolicyVm.__default.CmpStr((a).dtor_s, (b).dtor_s));
        }
      } else {
        return PolicyVm.Option.create_None();
      }
    };
    static StartsWith(s, p) {
      return ((new BigNumber((p).length)).isLessThanOrEqualTo(new BigNumber((s).length))) && (_dafny.areEqual((s).slice(0, new BigNumber((p).length)), p));
    };
    static ExistsStrEq(xs, t) {
      return ((_dafny.ZERO).isLessThan(new BigNumber((xs).length))) && (((((xs)[_dafny.ZERO]).is_VStr) && (_dafny.areEqual(((xs)[_dafny.ZERO]).dtor_s, t))) || (PolicyVm.__default.ExistsStrEq((xs).slice(_dafny.ONE), t)));
    };
    static TypeTagMatch(v, t) {
      let _source0 = v;
      {
        if (_source0.is_VStr) {
          let _0_s = (_source0).s;
          return PolicyVm.Option.create_Some((_dafny.areEqual(_0_s, t)) || (PolicyVm.__default.StartsWith(_0_s, _dafny.Seq.Concat(t, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("::"))))));
        }
      }
      {
        if (_source0.is_VObj) {
          let _1_es = (_source0).es;
          let _2_ty = ((PolicyVm.__default.Has(_1_es, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("type")))) ? (PolicyVm.__default.Get(_1_es, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("type")))) : (PolicyVm.Value.create_VUndef()));
          let _3_tg = ((PolicyVm.__default.Has(_1_es, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("tags")))) ? (PolicyVm.__default.Get(_1_es, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("tags")))) : (PolicyVm.Value.create_VUndef()));
          let _4_d1 = (_2_ty).is_VStr;
          let _5_m1 = (_4_d1) && ((_dafny.areEqual((_2_ty).dtor_s, t)) || (PolicyVm.__default.StartsWith((_2_ty).dtor_s, _dafny.Seq.Concat(t, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("::"))))));
          let _6_d2 = (_3_tg).is_VArr;
          let _7_m2 = (_6_d2) && (PolicyVm.__default.ExistsStrEq((_3_tg).dtor_xs, t));
          if ((_4_d1) || (_6_d2)) {
            return PolicyVm.Option.create_Some((_5_m1) || (_7_m2));
          } else {
            return PolicyVm.Option.create_None();
          }
        }
      }
      {
        return PolicyVm.Option.create_None();
      }
    };
    static StrsOf(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, ((((xs)[_dafny.ZERO]).is_VStr) ? (_dafny.Seq.of(((xs)[_dafny.ZERO]).dtor_s)) : (_dafny.Seq.of())));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static Neighbours(es, node) {
      if ((PolicyVm.__default.Forbidden(node)) || (!(PolicyVm.__default.Has(es, node)))) {
        return _dafny.Seq.of();
      } else {
        let _source0 = PolicyVm.__default.Get(es, node);
        {
          if (_source0.is_VStr) {
            let _0_s = (_source0).s;
            return _dafny.Seq.of(_0_s);
          }
        }
        {
          if (_source0.is_VArr) {
            let _1_xs = (_source0).xs;
            return PolicyVm.__default.StrsOf(_1_xs);
          }
        }
        {
          return _dafny.Seq.of();
        }
      }
    };
    static AddNs(ns, seen, q) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((ns).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Tuple.of(seen, q);
        } else if ((seen).contains((ns)[_dafny.ZERO])) {
          let _in0 = (ns).slice(_dafny.ONE);
          let _in1 = seen;
          let _in2 = q;
          ns = _in0;
          seen = _in1;
          q = _in2;
          continue TAIL_CALL_START;
        } else {
          let _in3 = (ns).slice(_dafny.ONE);
          let _in4 = (seen).Union(_dafny.Set.fromElements((ns)[_dafny.ZERO]));
          let _in5 = _dafny.Seq.Concat(q, _dafny.Seq.of((ns)[_dafny.ZERO]));
          ns = _in3;
          seen = _in4;
          q = _in5;
          continue TAIL_CALL_START;
        }
      }
    };
    static Bfs(es, q, qi, seen, visited) {
      TAIL_CALL_START: while (true) {
        if (((new BigNumber((q).length)).isLessThanOrEqualTo(qi)) || ((PolicyVm.__default.MaxClosure).isLessThanOrEqualTo(visited))) {
          return seen;
        } else {
          let _0_r = PolicyVm.__default.AddNs(PolicyVm.__default.Neighbours(es, (q)[qi]), seen, q);
          let _in0 = es;
          let _in1 = (_0_r)[1];
          let _in2 = (qi).plus(_dafny.ONE);
          let _in3 = (_0_r)[0];
          let _in4 = (visited).plus(_dafny.ONE);
          es = _in0;
          q = _in1;
          qi = _in2;
          seen = _in3;
          visited = _in4;
          continue TAIL_CALL_START;
        }
      }
    };
    static Closure(start, es) {
      return PolicyVm.__default.Bfs(es, _dafny.Seq.of(start), _dafny.ZERO, _dafny.Set.fromElements(start), _dafny.ZERO);
    };
    static ParseGlob(g, i, acc) {
      TAIL_CALL_START: while (true) {
        if ((i).isEqualTo(new BigNumber((g).length))) {
          return PolicyVm.Option.create_Some(acc);
        } else if (((g)[i]) === (92)) {
          if ((new BigNumber((g).length)).isLessThanOrEqualTo((i).plus(_dafny.ONE))) {
            return PolicyVm.Option.create_None();
          } else {
            let _in0 = g;
            let _in1 = (i).plus(new BigNumber(2));
            let _in2 = _dafny.Seq.Concat(acc, _dafny.Seq.of(PolicyVm.GTok.create_GLit((g)[(i).plus(_dafny.ONE)])));
            g = _in0;
            i = _in1;
            acc = _in2;
            continue TAIL_CALL_START;
          }
        } else if (((g)[i]) === (42)) {
          let _in3 = g;
          let _in4 = (i).plus(_dafny.ONE);
          let _in5 = ((((_dafny.ZERO).isLessThan(new BigNumber((acc).length))) && (((acc)[(new BigNumber((acc).length)).minus(_dafny.ONE)]).is_GStar)) ? (acc) : (_dafny.Seq.Concat(acc, _dafny.Seq.of(PolicyVm.GTok.create_GStar()))));
          g = _in3;
          i = _in4;
          acc = _in5;
          continue TAIL_CALL_START;
        } else if (((g)[i]) === (63)) {
          let _in6 = g;
          let _in7 = (i).plus(_dafny.ONE);
          let _in8 = _dafny.Seq.Concat(acc, _dafny.Seq.of(PolicyVm.GTok.create_GOne()));
          g = _in6;
          i = _in7;
          acc = _in8;
          continue TAIL_CALL_START;
        } else {
          let _in9 = g;
          let _in10 = (i).plus(_dafny.ONE);
          let _in11 = _dafny.Seq.Concat(acc, _dafny.Seq.of(PolicyVm.GTok.create_GLit((g)[i])));
          g = _in9;
          i = _in10;
          acc = _in11;
          continue TAIL_CALL_START;
        }
      }
    };
    static Gm(t, s) {
      if ((new BigNumber((t).length)).isEqualTo(_dafny.ZERO)) {
        return (new BigNumber((s).length)).isEqualTo(_dafny.ZERO);
      } else {
        let _source0 = (t)[_dafny.ZERO];
        {
          if (_source0.is_GStar) {
            return (PolicyVm.__default.Gm((t).slice(_dafny.ONE), s)) || (((_dafny.ZERO).isLessThan(new BigNumber((s).length))) && (PolicyVm.__default.Gm(t, (s).slice(_dafny.ONE))));
          }
        }
        {
          if (_source0.is_GOne) {
            return ((_dafny.ZERO).isLessThan(new BigNumber((s).length))) && (PolicyVm.__default.Gm((t).slice(_dafny.ONE), (s).slice(_dafny.ONE)));
          }
        }
        {
          let _0_c = (_source0).c;
          return (((_dafny.ZERO).isLessThan(new BigNumber((s).length))) && (((s)[_dafny.ZERO]) === (_0_c))) && (PolicyVm.__default.Gm((t).slice(_dafny.ONE), (s).slice(_dafny.ONE)));
        }
      }
    };
    static GlobFullCounted(t, s) {
      let r = false;
      let steps = _dafny.ZERO;
      let _0_n;
      _0_n = new BigNumber((s).length);
      let _1_prev;
      let _nw0 = Array(((_0_n).plus(_dafny.ONE)).toNumber()).fill(false);
      _1_prev = _nw0;
      let _2_k;
      _2_k = _dafny.ZERO;
      while ((_2_k).isLessThanOrEqualTo(_0_n)) {
        (_1_prev)[(_2_k)] = (_2_k).isEqualTo(_0_n);
        _2_k = (_2_k).plus(_dafny.ONE);
      }
      let _3_i;
      _3_i = new BigNumber((t).length);
      steps = (_0_n).plus(_dafny.ONE);
      while ((_dafny.ZERO).isLessThan(_3_i)) {
        _3_i = (_3_i).minus(_dafny.ONE);
        let _4_cur;
        let _nw1 = Array(((_0_n).plus(_dafny.ONE)).toNumber()).fill(false);
        _4_cur = _nw1;
        let _5_j;
        _5_j = _0_n;
        while ((_dafny.ZERO).isLessThanOrEqualTo(_5_j)) {
          let _source0 = (t)[_3_i];
          Lmatch0: {
            {
              if (_source0.is_GStar) {
                {
                  (_4_cur)[(_5_j)] = ((_1_prev)[_5_j]) || (((_5_j).isLessThan(_0_n)) && ((_4_cur)[(_5_j).plus(_dafny.ONE)]));
                }
                break Lmatch0;
              }
            }
            {
              if (_source0.is_GOne) {
                {
                  (_4_cur)[(_5_j)] = ((_5_j).isLessThan(_0_n)) && ((_1_prev)[(_5_j).plus(_dafny.ONE)]);
                }
                break Lmatch0;
              }
            }
            {
              let _6_c = (_source0).c;
              {
                (_4_cur)[(_5_j)] = (((_5_j).isLessThan(_0_n)) && (((s)[_5_j]) === (_6_c))) && ((_1_prev)[(_5_j).plus(_dafny.ONE)]);
              }
            }
          }
          _5_j = (_5_j).minus(_dafny.ONE);
        }
        _1_prev = _4_cur;
        steps = (steps).plus((_0_n).plus(_dafny.ONE));
      }
      r = (_1_prev)[_dafny.ZERO];
      return [r, steps];
    }
    static GlobFull(t, s) {
      let _hresult = false;
      let _0_r;
      let _1_st;
      let _out0;
      let _out1;
      let _outcollector0 = PolicyVm.__default.GlobFullCounted(t, s);
      _out0 = _outcollector0[0];
      _out1 = _outcollector0[1];
      _0_r = _out0;
      _1_st = _out1;
      _hresult = _0_r;
      return _hresult;
      return _hresult;
    }
    static ParamsRooted(s) {
      return (_dafny.areEqual(s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("action.params")))) || (PolicyVm.__default.StartsWith(s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("action.params."))));
    };
    static ParamsAvail(ctx) {
      return PolicyVm.__default.IsObjLike(PolicyVm.__default.Field(PolicyVm.__default.Field(ctx, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("action"))), PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("params"))));
    };
    static Operand(c, ctx) {
      let _0_refV = PolicyVm.__default.Field(c, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("ref")));
      if (!((_0_refV).is_VUndef)) {
        let _1_r = PolicyVm.__default.ResolvePath(ctx, _0_refV);
        if ((_1_r).dtor_found) {
          return PolicyVm.Option.create_Some((_1_r).dtor_v);
        } else {
          return PolicyVm.Option.create_None();
        }
      } else {
        let _2_vv = PolicyVm.__default.Field(c, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("value")));
        if ((_2_vv).is_VUndef) {
          return PolicyVm.Option.create_None();
        } else {
          return PolicyVm.Option.create_Some(_2_vv);
        }
      }
    };
    static ExistsDeepEq(v, xs) {
      return ((_dafny.ZERO).isLessThan(new BigNumber((xs).length))) && ((PolicyVm.__default.DeepEq(v, (xs)[_dafny.ZERO])) || (PolicyVm.__default.ExistsDeepEq(v, (xs).slice(_dafny.ONE))));
    };
    static B2T(b) {
      if (b) {
        return PolicyVm.Tri.create_TT();
      } else {
        return PolicyVm.Tri.create_TF();
      }
    };
    static LeafOp(op, v, operand, rx) {
      if (_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("eq")))) {
        return PolicyVm.__default.B2T(PolicyVm.__default.DeepEq(v, operand));
      } else if (_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("ne")))) {
        return PolicyVm.__default.B2T(!(PolicyVm.__default.DeepEq(v, operand)));
      } else if (_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("in")))) {
        if ((operand).is_VArr) {
          return PolicyVm.__default.B2T(PolicyVm.__default.ExistsDeepEq(v, (operand).dtor_xs));
        } else {
          return PolicyVm.Tri.create_TU();
        }
      } else if (_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("nin")))) {
        if ((operand).is_VArr) {
          return PolicyVm.__default.B2T(!(PolicyVm.__default.ExistsDeepEq(v, (operand).dtor_xs)));
        } else {
          return PolicyVm.Tri.create_TU();
        }
      } else if ((((_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("lt")))) || (_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("lte"))))) || (_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("gt"))))) || (_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("gte"))))) {
        let _source0 = PolicyVm.__default.Ordered(v, operand);
        {
          if (_source0.is_None) {
            return PolicyVm.Tri.create_TU();
          }
        }
        {
          let _0_o = (_source0).v;
          return PolicyVm.__default.B2T(((_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("lt")))) ? ((_0_o).isLessThan(_dafny.ZERO)) : (((_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("lte")))) ? ((_0_o).isLessThanOrEqualTo(_dafny.ZERO)) : (((_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("gt")))) ? ((_dafny.ZERO).isLessThan(_0_o)) : ((_dafny.ZERO).isLessThanOrEqualTo(_0_o))))))));
        }
      } else if (_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("prefix")))) {
        if (((v).is_VStr) && ((operand).is_VStr)) {
          return PolicyVm.__default.B2T(PolicyVm.__default.StartsWith((v).dtor_s, (operand).dtor_s));
        } else {
          return PolicyVm.Tri.create_TU();
        }
      } else if (_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("like")))) {
        if (!(((v).is_VStr) && ((operand).is_VStr))) {
          return PolicyVm.Tri.create_TU();
        } else if (((PolicyVm.__default.MaxLikePatternLen).isLessThan(new BigNumber(((operand).dtor_s).length))) || ((PolicyVm.__default.MaxPatternSubjectLen).isLessThan(new BigNumber(((v).dtor_s).length)))) {
          return PolicyVm.Tri.create_TU();
        } else {
          let _source1 = PolicyVm.__default.ParseGlob((operand).dtor_s, _dafny.ZERO, _dafny.Seq.of());
          {
            if (_source1.is_None) {
              return PolicyVm.Tri.create_TU();
            }
          }
          {
            let _1_t = (_source1).v;
            return PolicyVm.__default.B2T(PolicyVm.__default.GlobFull(_1_t, (v).dtor_s));
          }
        }
      } else if (_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("matches")))) {
        if (!(((v).is_VStr) && ((operand).is_VStr))) {
          return PolicyVm.Tri.create_TU();
        } else if (((PolicyVm.__default.MaxMatchesPatternLen).isLessThan(new BigNumber(((operand).dtor_s).length))) || ((PolicyVm.__default.MaxPatternSubjectLen).isLessThan(new BigNumber(((v).dtor_s).length)))) {
          return PolicyVm.Tri.create_TU();
        } else if (!(((rx).dtor_safe)((operand).dtor_s))) {
          return PolicyVm.Tri.create_TU();
        } else {
          let _source2 = ((rx).dtor_full)((operand).dtor_s, (v).dtor_s);
          {
            if (_source2.is_None) {
              return PolicyVm.Tri.create_TU();
            }
          }
          {
            let _2_b = (_source2).v;
            return PolicyVm.__default.B2T(_2_b);
          }
        }
      } else if (_dafny.areEqual(op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("is_a")))) {
        if (!(((operand).is_VStr) && ((_dafny.ZERO).isLessThan(new BigNumber(((operand).dtor_s).length))))) {
          return PolicyVm.Tri.create_TU();
        } else {
          let _source3 = PolicyVm.__default.TypeTagMatch(v, (operand).dtor_s);
          {
            if (_source3.is_None) {
              return PolicyVm.Tri.create_TU();
            }
          }
          {
            let _3_b = (_source3).v;
            return PolicyVm.__default.B2T(_3_b);
          }
        }
      } else {
        return PolicyVm.Tri.create_TU();
      }
    };
    static MemberOfLeaf(c, ctx, v) {
      if (!((v).is_VStr)) {
        return PolicyVm.Tri.create_TU();
      } else {
        let _0_cv = PolicyVm.__default.Field(c, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("collection")));
        if ((!((_0_cv).is_VStr)) || ((new BigNumber(((_0_cv).dtor_s).length)).isEqualTo(_dafny.ZERO))) {
          return PolicyVm.Tri.create_TU();
        } else {
          let _1_coll = PolicyVm.__default.ResolvePath(ctx, _0_cv);
          if ((!((_1_coll).dtor_found)) || (!(PolicyVm.__default.IsObjRec((_1_coll).dtor_v)))) {
            return PolicyVm.Tri.create_TU();
          } else {
            let _source0 = PolicyVm.__default.Operand(c, ctx);
            {
              if (_source0.is_None) {
                return PolicyVm.Tri.create_TU();
              }
            }
            {
              let _2_opd = (_source0).v;
              let _3_targets = (((_2_opd).is_VArr) ? (PolicyVm.__default.StrsOf((_2_opd).dtor_xs)) : ((((_2_opd).is_VStr) ? (_dafny.Seq.of((_2_opd).dtor_s)) : (_dafny.Seq.of()))));
              if ((new BigNumber((_3_targets).length)).isEqualTo(_dafny.ZERO)) {
                return PolicyVm.Tri.create_TU();
              } else {
                let _4_reach = PolicyVm.__default.Closure((v).dtor_s, ((_1_coll).dtor_v).dtor_es);
                return PolicyVm.__default.B2T(_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((_3_targets).length)), false, function (_exists_var_0) {
                  let _5_i = _exists_var_0;
                  return (((_dafny.ZERO).isLessThanOrEqualTo(_5_i)) && ((_5_i).isLessThan(new BigNumber((_3_targets).length)))) && ((_4_reach).contains((_3_targets)[_5_i]));
                }));
              }
            }
          }
        }
      }
    };
    static TriLeaf(c, ctx, rx) {
      let _0_fv = PolicyVm.__default.Field(c, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("field")));
      let _1_ov = PolicyVm.__default.Field(c, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("op")));
      let _2_rv = PolicyVm.__default.Field(c, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("ref")));
      if ((!((_0_fv).is_VStr)) || ((new BigNumber(((_0_fv).dtor_s).length)).isEqualTo(_dafny.ZERO))) {
        return PolicyVm.Tri.create_TU();
      } else if (!((_1_ov).is_VStr)) {
        return PolicyVm.Tri.create_TU();
      } else if ((PolicyVm.__default.ParamsRooted((_0_fv).dtor_s)) && (!(PolicyVm.__default.ParamsAvail(ctx)))) {
        return PolicyVm.Tri.create_TU();
      } else if ((((_2_rv).is_VStr) && (PolicyVm.__default.ParamsRooted((_2_rv).dtor_s))) && (!(PolicyVm.__default.ParamsAvail(ctx)))) {
        return PolicyVm.Tri.create_TU();
      } else {
        let _3_f = PolicyVm.__default.ResolvePath(ctx, _0_fv);
        let _4_op = (_1_ov).dtor_s;
        if (_dafny.areEqual(_4_op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("exists")))) {
          if (_dafny.areEqual(PolicyVm.__default.Field(c, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("value"))), PolicyVm.Value.create_VBool(false))) {
            return PolicyVm.__default.B2T(!((_3_f).dtor_found));
          } else {
            return PolicyVm.__default.B2T((_3_f).dtor_found);
          }
        } else if (!((_3_f).dtor_found)) {
          return PolicyVm.Tri.create_TU();
        } else if (_dafny.areEqual(_4_op, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("member_of")))) {
          return PolicyVm.__default.MemberOfLeaf(c, ctx, (_3_f).dtor_v);
        } else {
          let _source0 = PolicyVm.__default.Operand(c, ctx);
          {
            if (_source0.is_None) {
              return PolicyVm.Tri.create_TU();
            }
          }
          {
            let _5_operand = (_source0).v;
            return PolicyVm.__default.LeafOp(_4_op, (_3_f).dtor_v, _5_operand, rx);
          }
        }
      }
    };
    static EvalTriC(c, ctx, rx) {
      let _source0 = c;
      {
        if (_source0.is_VObj) {
          let _0_es = (_source0).es;
          if (PolicyVm.__default.Has(_0_es, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("all_of")))) {
            let _1_a = PolicyVm.__default.Get(_0_es, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("all_of")));
            if ((!((_1_a).is_VArr)) || ((new BigNumber(((_1_a).dtor_xs).length)).isEqualTo(_dafny.ZERO))) {
              return _dafny.Tuple.of(PolicyVm.Tri.create_TU(), _dafny.ONE);
            } else {
              let _2_r = PolicyVm.__default.EvalAllC((_1_a).dtor_xs, ctx, rx, false);
              return _dafny.Tuple.of((_2_r)[0], (_dafny.ONE).plus((_2_r)[1]));
            }
          } else if (PolicyVm.__default.Has(_0_es, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("any_of")))) {
            let _3_a = PolicyVm.__default.Get(_0_es, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("any_of")));
            if ((!((_3_a).is_VArr)) || ((new BigNumber(((_3_a).dtor_xs).length)).isEqualTo(_dafny.ZERO))) {
              return _dafny.Tuple.of(PolicyVm.Tri.create_TU(), _dafny.ONE);
            } else {
              let _4_r = PolicyVm.__default.EvalAnyC((_3_a).dtor_xs, ctx, rx, false);
              return _dafny.Tuple.of((_4_r)[0], (_dafny.ONE).plus((_4_r)[1]));
            }
          } else if (PolicyVm.__default.Has(_0_es, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("not")))) {
            let _5_r = PolicyVm.__default.EvalTriC(PolicyVm.__default.Get(_0_es, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("not"))), ctx, rx);
            return _dafny.Tuple.of(PolicyVm.__default.NotT((_5_r)[0]), (_dafny.ONE).plus((_5_r)[1]));
          } else {
            return _dafny.Tuple.of(PolicyVm.__default.TriLeaf(c, ctx, rx), _dafny.ONE);
          }
        }
      }
      {
        return _dafny.Tuple.of(PolicyVm.Tri.create_TU(), _dafny.ONE);
      }
    };
    static EvalAllC(xs, ctx, rx, sawU) {
      if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Tuple.of(((sawU) ? (PolicyVm.Tri.create_TU()) : (PolicyVm.Tri.create_TT())), _dafny.ZERO);
      } else {
        let _0_r = PolicyVm.__default.EvalTriC((xs)[_dafny.ZERO], ctx, rx);
        if (_dafny.areEqual((_0_r)[0], PolicyVm.Tri.create_TF())) {
          return _dafny.Tuple.of(PolicyVm.Tri.create_TF(), (_0_r)[1]);
        } else {
          let _1_q = PolicyVm.__default.EvalAllC((xs).slice(_dafny.ONE), ctx, rx, (sawU) || (_dafny.areEqual((_0_r)[0], PolicyVm.Tri.create_TU())));
          return _dafny.Tuple.of((_1_q)[0], ((_0_r)[1]).plus((_1_q)[1]));
        }
      }
    };
    static EvalAnyC(xs, ctx, rx, sawU) {
      if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Tuple.of(((sawU) ? (PolicyVm.Tri.create_TU()) : (PolicyVm.Tri.create_TF())), _dafny.ZERO);
      } else {
        let _0_r = PolicyVm.__default.EvalTriC((xs)[_dafny.ZERO], ctx, rx);
        if (_dafny.areEqual((_0_r)[0], PolicyVm.Tri.create_TT())) {
          return _dafny.Tuple.of(PolicyVm.Tri.create_TT(), (_0_r)[1]);
        } else {
          let _1_q = PolicyVm.__default.EvalAnyC((xs).slice(_dafny.ONE), ctx, rx, (sawU) || (_dafny.areEqual((_0_r)[0], PolicyVm.Tri.create_TU())));
          return _dafny.Tuple.of((_1_q)[0], ((_0_r)[1]).plus((_1_q)[1]));
        }
      }
    };
    static EvalTri(c, ctx, rx) {
      return (PolicyVm.__default.EvalTriC(c, ctx, rx))[0];
    };
    static EvalCond(c, ctx, rx) {
      return _dafny.areEqual(PolicyVm.__default.EvalTri(c, ctx, rx), PolicyVm.Tri.create_TT());
    };
    static MapNot(ts) {
      return _dafny.Seq.Create(new BigNumber((ts).length), ((_0_ts) => function (_1_i) {
        return PolicyVm.__default.NotT((_0_ts)[_1_i]);
      })(ts));
    };
    static PointRefines(a, b) {
      return ((new BigNumber((a).length)).isEqualTo(new BigNumber((b).length))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((a).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((a).length)))) || (PolicyVm.__default.Refines((a)[_0_i], (b)[_0_i]));
      }));
    };
    static Results(xs, ctx, rx) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(PolicyVm.__default.EvalTri((xs)[_dafny.ZERO], ctx, rx)));
          let _in0 = (xs).slice(_dafny.ONE);
          let _in1 = ctx;
          let _in2 = rx;
          xs = _in0;
          ctx = _in1;
          rx = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static EvalBudgeted(c, ctx, rx, budget) {
      if ((budget).isLessThan(PolicyVm.__default.SzV(c))) {
        return PolicyVm.Option.create_None();
      } else {
        return PolicyVm.Option.create_Some(PolicyVm.__default.EvalTri(c, ctx, rx));
      }
    };
    static ExistsVerb(xs, verb) {
      return ((_dafny.ZERO).isLessThan(new BigNumber((xs).length))) && (((((xs)[_dafny.ZERO]).is_VStr) && ((_dafny.areEqual(((xs)[_dafny.ZERO]).dtor_s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("*")))) || (_dafny.areEqual(((xs)[_dafny.ZERO]).dtor_s, verb)))) || (PolicyVm.__default.ExistsVerb((xs).slice(_dafny.ONE), verb)));
    };
    static VerbMatches(pv, verb) {
      let _source0 = pv;
      {
        if (_source0.is_VStr) {
          let _0_s = (_source0).s;
          return (_dafny.areEqual(_0_s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("*")))) || (_dafny.areEqual(_0_s, verb));
        }
      }
      {
        if (_source0.is_VArr) {
          let _1_xs = (_source0).xs;
          return PolicyVm.__default.ExistsVerb(_1_xs, verb);
        }
      }
      {
        return false;
      }
    };
    static EndsStar(s) {
      return ((_dafny.ZERO).isLessThan(new BigNumber((s).length))) && (((s)[(new BigNumber((s).length)).minus(_dafny.ONE)]) === (42));
    };
    static ResourceMatches(pattern, resource, rx) {
      if ((pattern).is_VUndef) {
        return true;
      } else if (!((pattern).is_VStr)) {
        return false;
      } else {
        let _0_p = (pattern).dtor_s;
        if (_dafny.areEqual(_0_p, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("*")))) {
          return true;
        } else if (PolicyVm.__default.StartsWith(_0_p, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("re:")))) {
          let _1_src = (_0_p).slice(new BigNumber(3));
          if ((new BigNumber(200)).isLessThan(new BigNumber((_1_src).length))) {
            return false;
          } else if ((PolicyVm.__default.MaxReResourceLen).isLessThan(new BigNumber((resource).length))) {
            return false;
          } else if (!(((rx).dtor_safe)(_1_src))) {
            return false;
          } else {
            return _dafny.areEqual(((rx).dtor_full)(_1_src, resource), PolicyVm.Option.create_Some(true));
          }
        } else if (PolicyVm.__default.EndsStar(_0_p)) {
          return PolicyVm.__default.StartsWith(resource, (_0_p).slice(0, (new BigNumber((_0_p).length)).minus(_dafny.ONE)));
        } else {
          return _dafny.areEqual(_0_p, resource);
        }
      }
    };
    static WhereAll(ws, ctx, rx) {
      return ((new BigNumber((ws).length)).isEqualTo(_dafny.ZERO)) || ((PolicyVm.__default.EvalCond((ws)[_dafny.ZERO], ctx, rx)) && (PolicyVm.__default.WhereAll((ws).slice(_dafny.ONE), ctx, rx)));
    };
    static PreOk(p, ctx, rx) {
      let _pat_let_tv0 = p;
      let _pat_let_tv1 = p;
      let _pat_let_tv2 = rx;
      return (PolicyVm.__default.IsObjLike(p)) && (function (_pat_let0_0) {
        return function (_0_a) {
          return function (_pat_let1_0) {
            return function (_1_verb) {
              return function (_pat_let2_0) {
                return function (_2_res) {
                  return ((((_1_verb).is_VStr) && ((_2_res).is_VStr)) && (PolicyVm.__default.VerbMatches(PolicyVm.__default.Field(_pat_let_tv0, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("verb"))), (_1_verb).dtor_s))) && (PolicyVm.__default.ResourceMatches(PolicyVm.__default.Field(_pat_let_tv1, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("resource"))), (_2_res).dtor_s, _pat_let_tv2));
                }(_pat_let2_0);
              }(PolicyVm.__default.Field(_0_a, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("resource"))));
            }(_pat_let1_0);
          }(PolicyVm.__default.Field(_0_a, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("verb"))));
        }(_pat_let0_0);
      }(PolicyVm.__default.Field(ctx, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("action")))));
    };
    static PredicateMatches(p, ctx, rx) {
      let _pat_let_tv0 = ctx;
      let _pat_let_tv1 = rx;
      return (PolicyVm.__default.PreOk(p, ctx, rx)) && (function (_pat_let3_0) {
        return function (_0_w) {
          return ((_0_w).is_VUndef) || (((_0_w).is_VArr) && (PolicyVm.__default.WhereAll((_0_w).dtor_xs, _pat_let_tv0, _pat_let_tv1)));
        }(_pat_let3_0);
      }(PolicyVm.__default.Field(p, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("where")))));
    };
    static FirstMatch(xs, ctx, rx) {
      if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
        return new BigNumber(-1);
      } else if (PolicyVm.__default.PredicateMatches((xs)[_dafny.ZERO], ctx, rx)) {
        return _dafny.ZERO;
      } else {
        let _0_r = PolicyVm.__default.FirstMatch((xs).slice(_dafny.ONE), ctx, rx);
        if ((_0_r).isLessThan(_dafny.ZERO)) {
          return new BigNumber(-1);
        } else {
          return (_0_r).plus(_dafny.ONE);
        }
      }
    };
    static EvalPredicates(ps, ctx, rx) {
      if ((!((ps).is_VArr)) || ((new BigNumber(((ps).dtor_xs).length)).isEqualTo(_dafny.ZERO))) {
        return PolicyVm.PredRes.create_PredRes(false, new BigNumber(-1), _dafny.ONE);
      } else {
        let _0_i = PolicyVm.__default.FirstMatch((ps).dtor_xs, ctx, rx);
        if ((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) {
          return PolicyVm.PredRes.create_PredRes(true, _0_i, _dafny.ZERO);
        } else {
          return PolicyVm.PredRes.create_PredRes(false, new BigNumber(-1), new BigNumber(2));
        }
      }
    };
    static ClassIndex(s) {
      if (_dafny.areEqual(s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("reversible")))) {
        return _dafny.ZERO;
      } else if (_dafny.areEqual(s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("rate_limited")))) {
        return _dafny.ONE;
      } else if (_dafny.areEqual(s, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("irreversible")))) {
        return new BigNumber(2);
      } else {
        return new BigNumber(-1);
      }
    };
    static CountIn(xs, lo, hi) {
      let _0___accumulator = _dafny.ZERO;
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return (_dafny.ZERO).plus(_0___accumulator);
        } else {
          _0___accumulator = (_0___accumulator).plus(((((((xs)[_dafny.ZERO]).is_VNum) && ((lo).isLessThan(((xs)[_dafny.ZERO]).dtor_r))) && ((((xs)[_dafny.ZERO]).dtor_r).isAtMost(hi))) ? (_dafny.ONE) : (_dafny.ZERO)));
          let _in0 = (xs).slice(_dafny.ONE);
          let _in1 = lo;
          let _in2 = hi;
          xs = _in0;
          lo = _in1;
          hi = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static EnvelopeEv(cv, ctx, fl) {
      if ((!(PolicyVm.__default.IsObjLike(cv))) || (!(PolicyVm.__default.IsObjLike(ctx)))) {
        return false;
      } else {
        let _0_now = PolicyVm.__default.Field(ctx, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("now")));
        if (!((_0_now).is_VNum)) {
          return false;
        } else {
          let _1_ty = PolicyVm.__default.Field(cv, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("type")));
          if (!((_1_ty).is_VStr)) {
            return false;
          } else {
            let _2_t = (_1_ty).dtor_s;
            if (_dafny.areEqual(_2_t, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("expires")))) {
              let _3_at = PolicyVm.__default.Field(cv, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("at")));
              return ((_3_at).is_VNum) && (((_0_now).dtor_r).isLessThan((_3_at).dtor_r));
            } else if (_dafny.areEqual(_2_t, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("not_before")))) {
              let _4_at = PolicyVm.__default.Field(cv, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("at")));
              return ((_4_at).is_VNum) && (((_4_at).dtor_r).isAtMost((_0_now).dtor_r));
            } else if (_dafny.areEqual(_2_t, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("rate")))) {
              let _5_mx = PolicyVm.__default.Field(cv, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("max")));
              let _6_per = PolicyVm.__default.Field(cv, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("per_secs")));
              if (!((((_5_mx).is_VNum) && ((_6_per).is_VNum)) && ((new _dafny.BigRational(new BigNumber("0"))).isLessThan((_6_per).dtor_r)))) {
                return false;
              } else {
                let _7_rec = PolicyVm.__default.Field(ctx, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("recentActionTimes")));
                if (!((_7_rec).is_VArr)) {
                  return false;
                } else {
                  return (new _dafny.BigRational((PolicyVm.__default.CountIn((_7_rec).dtor_xs, (fl)((_0_now).dtor_r, (_6_per).dtor_r), (_0_now).dtor_r)), new BigNumber(1))).isLessThan((_5_mx).dtor_r);
                }
              }
            } else if (_dafny.areEqual(_2_t, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("max_blast_radius")))) {
              let _8_mx = PolicyVm.__default.Field(cv, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("max")));
              let _9_bl = PolicyVm.__default.Field(ctx, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("blastRadius")));
              return (((_8_mx).is_VNum) && ((_9_bl).is_VNum)) && (((_9_bl).dtor_r).isAtMost((_8_mx).dtor_r));
            } else if (_dafny.areEqual(_2_t, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("reversibility_max")))) {
              let _10_c = PolicyVm.__default.Field(cv, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("class")));
              let _11_rc = PolicyVm.__default.Field(ctx, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("reversibilityClass")));
              return (((_10_c).is_VStr) && ((_11_rc).is_VStr)) && (function (_pat_let4_0) {
                return function (_12_lim) {
                  return function (_pat_let5_0) {
                    return function (_13_cur) {
                      return (((_dafny.ZERO).isLessThanOrEqualTo(_12_lim)) && ((_dafny.ZERO).isLessThanOrEqualTo(_13_cur))) && ((_13_cur).isLessThanOrEqualTo(_12_lim));
                    }(_pat_let5_0);
                  }(PolicyVm.__default.ClassIndex((_11_rc).dtor_s));
                }(_pat_let4_0);
              }(PolicyVm.__default.ClassIndex((_10_c).dtor_s)));
            } else if (_dafny.areEqual(_2_t, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("delegation_depth")))) {
              let _14_mx = PolicyVm.__default.Field(cv, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("max")));
              let _15_d = PolicyVm.__default.Field(ctx, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("delegationDepth")));
              return (((_14_mx).is_VNum) && ((_15_d).is_VNum)) && (((_15_d).dtor_r).isAtMost((_14_mx).dtor_r));
            } else if (_dafny.areEqual(_2_t, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("budget_alloc")))) {
              let _16_l = PolicyVm.__default.Field(cv, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("limit")));
              return ((_16_l).is_VNum) && ((new _dafny.BigRational(new BigNumber("0"))).isAtMost((_16_l).dtor_r));
            } else {
              return false;
            }
          }
        }
      }
    };
    static ExistsPred(xs, a, rx) {
      return ((_dafny.ZERO).isLessThan(new BigNumber((xs).length))) && ((PolicyVm.__default.PredicateMatches((xs)[_dafny.ZERO], a, rx)) || (PolicyVm.__default.ExistsPred((xs).slice(_dafny.ONE), a, rx)));
    };
    static AgentEv(cv, ctx, rx, fl, tool) {
      if ((!(PolicyVm.__default.IsObjRec(cv))) || (!(PolicyVm.__default.IsObjRec(ctx)))) {
        return false;
      } else {
        let _0_ty = PolicyVm.__default.Field(cv, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("type")));
        if (_dafny.areEqual(_0_ty, PolicyVm.Value.create_VStr(PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("tool_schema"))))) {
          return (tool)(cv, ctx);
        } else if (_dafny.areEqual(_0_ty, PolicyVm.Value.create_VStr(PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("predicates"))))) {
          let _1_a = PolicyVm.__default.Field(ctx, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("action")));
          let _2_allow = PolicyVm.__default.Field(cv, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("allow")));
          if ((!(PolicyVm.__default.IsObjRec(_1_a))) || (!((_2_allow).is_VArr))) {
            return false;
          } else {
            return PolicyVm.__default.ExistsPred((_2_allow).dtor_xs, _1_a, rx);
          }
        } else {
          return PolicyVm.__default.EnvelopeEv(cv, ctx, fl);
        }
      }
    };
    static CavName(cv) {
      let _0_t = PolicyVm.__default.Field(cv, PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("type")));
      if ((_0_t).is_VStr) {
        return (_0_t).dtor_s;
      } else {
        return PolicyVm.__default.MalformedName;
      }
    };
    static EvalCaveats(cs, ev) {
      if ((new BigNumber((cs).length)).isEqualTo(_dafny.ZERO)) {
        return PolicyVm.CavRes.create_CavRes(true, _dafny.Seq.of());
      } else {
        let _0_r = PolicyVm.__default.EvalCaveats((cs).slice(_dafny.ONE), ev);
        if ((ev)((cs)[_dafny.ZERO])) {
          return _0_r;
        } else {
          return PolicyVm.CavRes.create_CavRes(false, _dafny.Seq.Concat(_dafny.Seq.of(PolicyVm.__default.CavName((cs)[_dafny.ZERO])), (_0_r).dtor_failed));
        }
      }
    };
    static EvalCaveatList(cs, ev) {
      if ((cs).is_VArr) {
        return PolicyVm.__default.EvalCaveats((cs).dtor_xs, ev);
      } else {
        return PolicyVm.CavRes.create_CavRes(false, _dafny.Seq.of(PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("<malformed caveats>"))));
      }
    };
    static Clamp01(x) {
      if ((x).isLessThan(new _dafny.BigRational(new BigNumber("0")))) {
        return new _dafny.BigRational(new BigNumber("0"));
      } else if ((new _dafny.BigRational(new BigNumber("1"))).isLessThan(x)) {
        return new _dafny.BigRational(new BigNumber("1"));
      } else {
        return x;
      }
    };
    static Nz(x) {
      if ((new _dafny.BigRational(new BigNumber("0"))).isLessThan(x)) {
        return x;
      } else {
        return new _dafny.BigRational(new BigNumber("0"));
      }
    };
    static Cost(r, kappa) {
      return (PolicyVm.__default.Nz(kappa)).multipliedBy(PolicyVm.__default.Clamp01(r));
    };
    static ReqThr(r, th1, th2, irreversible) {
      if ((r).isAtMost(th1)) {
        return PolicyVm.Thr.create_Thr(_dafny.ONE, _dafny.ZERO, !(irreversible));
      } else if ((r).isAtMost(th2)) {
        return PolicyVm.Thr.create_Thr(new BigNumber(2), _dafny.ONE, false);
      } else {
        return PolicyVm.Thr.create_Thr(new BigNumber(3), new BigNumber(2), false);
      }
    };
    static Escalate(rt, minT) {
      let _0_t = ((((rt).dtor_t).isLessThan(minT)) ? (minT) : ((rt).dtor_t));
      let _1_floor = (_0_t).minus(_dafny.ONE);
      return PolicyVm.Thr.create_Thr(_0_t, (((_1_floor).isLessThanOrEqualTo((rt).dtor_proof)) ? ((rt).dtor_proof) : (_1_floor)), (((_dafny.ONE).isLessThan(_0_t)) ? (false) : ((rt).dtor_opt)));
    };
    static AdmitOf(t, bge) {
      if (((t).isLessThan(new BigNumber(3))) && (!(bge))) {
        return PolicyVm.Adm.create_Adm(false, true, new BigNumber(3), false);
      } else if ((t).isEqualTo(_dafny.ONE)) {
        return PolicyVm.Adm.create_Adm(true, false, _dafny.ONE, true);
      } else if ((t).isEqualTo(new BigNumber(2))) {
        return PolicyVm.Adm.create_Adm(false, true, new BigNumber(2), true);
      } else {
        return PolicyVm.Adm.create_Adm(false, true, new BigNumber(3), false);
      }
    };
    static DecideCore(prOk, cvOk, dcvOk, chainOk, rt, adm) {
      let _0_release = (((prOk) && (cvOk)) && (dcvOk)) && (chainOk);
      return PolicyVm.Dec.create_Dec(_0_release, (_0_release) && ((adm).dtor_admit), ((_0_release) ? ((adm).dtor_needStepUp) : (true)), PolicyVm.__default.Escalate(rt, (adm).dtor_t), (_0_release) && ((adm).dtor_metered));
    };
    static DecideAt(prOk, cvOk, dcvOk, chainOk, r, th1, th2, kappa, B, irreversible) {
      let _0_rt = PolicyVm.__default.ReqThr(r, th1, th2, irreversible);
      return PolicyVm.__default.DecideCore(prOk, cvOk, dcvOk, chainOk, _0_rt, PolicyVm.__default.AdmitOf((_0_rt).dtor_t, (PolicyVm.__default.Cost(r, kappa)).isAtMost(B)));
    };
    static RiskWithFloor(score, floor) {
      if ((floor).isAtMost(score)) {
        return score;
      } else {
        return floor;
      }
    };
    static Debit(B, c) {
      let _0_x = (B).minus(PolicyVm.__default.Nz(c));
      if ((new _dafny.BigRational(new BigNumber("0"))).isLessThan(_0_x)) {
        return _0_x;
      } else {
        return new _dafny.BigRational(new BigNumber("0"));
      }
    };
    static Leak(B, lambda, dtSecs) {
      let _0_x = (B).minus((PolicyVm.__default.Nz(lambda)).multipliedBy(dtSecs));
      if ((new _dafny.BigRational(new BigNumber("0"))).isLessThan(_0_x)) {
        return _0_x;
      } else {
        return new _dafny.BigRational(new BigNumber("0"));
      }
    };
    static Run(B, steps, kappa) {
      if ((new BigNumber((steps).length)).isEqualTo(_dafny.ZERO)) {
        return _dafny.Tuple.of(B, new _dafny.BigRational(new BigNumber("0")));
      } else {
        let _0_h = (steps)[_dafny.ZERO];
        let _source0 = _0_h;
        {
          if (_source0.is_LeakStep) {
            let _1_l = (_source0).lambda;
            let _2_dt = (_source0).dt;
            let _3_B2 = (((new _dafny.BigRational(new BigNumber("0"))).isAtMost(_2_dt)) ? (PolicyVm.__default.Leak(B, _1_l, _2_dt)) : (B));
            return PolicyVm.__default.Run(_3_B2, (steps).slice(_dafny.ONE), kappa);
          }
        }
        {
          let _4_r = (_source0).r;
          let _5_c = PolicyVm.__default.Cost(_4_r, kappa);
          if ((_5_c).isAtMost(B)) {
            let _6_q = PolicyVm.__default.Run((B).minus(_5_c), (steps).slice(_dafny.ONE), kappa);
            return _dafny.Tuple.of((_6_q)[0], ((_6_q)[1]).plus(_5_c));
          } else {
            return PolicyVm.__default.Run(B, (steps).slice(_dafny.ONE), kappa);
          }
        }
      }
    };
    static CaveatEvFor(cctx, rx, fl, tool) {
      return ((_0_cctx, _1_rx, _2_fl, _3_tool) => function (_4_cv) {
        return PolicyVm.__default.AgentEv(_4_cv, _0_cctx, _1_rx, _2_fl, _3_tool);
      })(cctx, rx, fl, tool);
    };
    static ReleaseOf(preds, action, caveats, extra, cctx, chainOk, rx, fl, tool) {
      return ((((PolicyVm.__default.EvalPredicates(preds, action, rx)).dtor_allowed) && ((PolicyVm.__default.EvalCaveatList(caveats, PolicyVm.__default.CaveatEvFor(cctx, rx, fl, tool))).dtor_ok)) && ((PolicyVm.__default.EvalCaveats(extra, PolicyVm.__default.CaveatEvFor(cctx, rx, fl, tool))).dtor_ok)) && (chainOk);
    };
    static get NotFound() {
      return PolicyVm.Res.create_Res(false, PolicyVm.Value.create_VUndef());
    };
    static get MaxClosure() {
      return new BigNumber(10000);
    };
    static get MaxLikePatternLen() {
      return new BigNumber(512);
    };
    static get MaxPatternSubjectLen() {
      return new BigNumber(512);
    };
    static get MaxMatchesPatternLen() {
      return new BigNumber(200);
    };
    static get MaxReResourceLen() {
      return new BigNumber(512);
    };
    static get MalformedName() {
      return PolicyVm.__default.S(_dafny.Seq.UnicodeFromString("<malformed>"));
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
        return "PolicyVm.Option.None";
      } else if (this.$tag === 1) {
        return "PolicyVm.Option.Some" + "(" + _dafny.toString(this.v) + ")";
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
      return PolicyVm.Option.create_None();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Option.Default();
        }
      };
    }
  }

  $module.U = class U {
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

  $module.Value = class Value {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_VNull() {
      let $dt = new Value(0);
      return $dt;
    }
    static create_VUndef() {
      let $dt = new Value(1);
      return $dt;
    }
    static create_VBool(b) {
      let $dt = new Value(2);
      $dt.b = b;
      return $dt;
    }
    static create_VNum(r) {
      let $dt = new Value(3);
      $dt.r = r;
      return $dt;
    }
    static create_VNonFinite() {
      let $dt = new Value(4);
      return $dt;
    }
    static create_VFn() {
      let $dt = new Value(5);
      return $dt;
    }
    static create_VStr(s) {
      let $dt = new Value(6);
      $dt.s = s;
      return $dt;
    }
    static create_VArr(xs) {
      let $dt = new Value(7);
      $dt.xs = xs;
      return $dt;
    }
    static create_VObj(es, plain) {
      let $dt = new Value(8);
      $dt.es = es;
      $dt.plain = plain;
      return $dt;
    }
    get is_VNull() { return this.$tag === 0; }
    get is_VUndef() { return this.$tag === 1; }
    get is_VBool() { return this.$tag === 2; }
    get is_VNum() { return this.$tag === 3; }
    get is_VNonFinite() { return this.$tag === 4; }
    get is_VFn() { return this.$tag === 5; }
    get is_VStr() { return this.$tag === 6; }
    get is_VArr() { return this.$tag === 7; }
    get is_VObj() { return this.$tag === 8; }
    get dtor_b() { return this.b; }
    get dtor_r() { return this.r; }
    get dtor_s() { return this.s; }
    get dtor_xs() { return this.xs; }
    get dtor_es() { return this.es; }
    get dtor_plain() { return this.plain; }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.Value.VNull";
      } else if (this.$tag === 1) {
        return "PolicyVm.Value.VUndef";
      } else if (this.$tag === 2) {
        return "PolicyVm.Value.VBool" + "(" + _dafny.toString(this.b) + ")";
      } else if (this.$tag === 3) {
        return "PolicyVm.Value.VNum" + "(" + _dafny.toString(this.r) + ")";
      } else if (this.$tag === 4) {
        return "PolicyVm.Value.VNonFinite";
      } else if (this.$tag === 5) {
        return "PolicyVm.Value.VFn";
      } else if (this.$tag === 6) {
        return "PolicyVm.Value.VStr" + "(" + _dafny.toString(this.s) + ")";
      } else if (this.$tag === 7) {
        return "PolicyVm.Value.VArr" + "(" + _dafny.toString(this.xs) + ")";
      } else if (this.$tag === 8) {
        return "PolicyVm.Value.VObj" + "(" + _dafny.toString(this.es) + ", " + _dafny.toString(this.plain) + ")";
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
        return other.$tag === 2 && this.b === other.b;
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.r, other.r);
      } else if (this.$tag === 4) {
        return other.$tag === 4;
      } else if (this.$tag === 5) {
        return other.$tag === 5;
      } else if (this.$tag === 6) {
        return other.$tag === 6 && _dafny.areEqual(this.s, other.s);
      } else if (this.$tag === 7) {
        return other.$tag === 7 && _dafny.areEqual(this.xs, other.xs);
      } else if (this.$tag === 8) {
        return other.$tag === 8 && _dafny.areEqual(this.es, other.es) && this.plain === other.plain;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return PolicyVm.Value.create_VNull();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Value.Default();
        }
      };
    }
  }

  $module.Entry = class Entry {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Entry(k, v) {
      let $dt = new Entry(0);
      $dt.k = k;
      $dt.v = v;
      return $dt;
    }
    get is_Entry() { return this.$tag === 0; }
    get dtor_k() { return this.k; }
    get dtor_v() { return this.v; }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.Entry.Entry" + "(" + _dafny.toString(this.k) + ", " + _dafny.toString(this.v) + ")";
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
      return PolicyVm.Entry.create_Entry(_dafny.Seq.of(), PolicyVm.Value.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Entry.Default();
        }
      };
    }
  }

  $module.Tri = class Tri {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_TT() {
      let $dt = new Tri(0);
      return $dt;
    }
    static create_TF() {
      let $dt = new Tri(1);
      return $dt;
    }
    static create_TU() {
      let $dt = new Tri(2);
      return $dt;
    }
    get is_TT() { return this.$tag === 0; }
    get is_TF() { return this.$tag === 1; }
    get is_TU() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield Tri.create_TT();
      yield Tri.create_TF();
      yield Tri.create_TU();
    }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.Tri.TT";
      } else if (this.$tag === 1) {
        return "PolicyVm.Tri.TF";
      } else if (this.$tag === 2) {
        return "PolicyVm.Tri.TU";
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
      return PolicyVm.Tri.create_TT();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Tri.Default();
        }
      };
    }
  }

  $module.Res = class Res {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Res(found, v) {
      let $dt = new Res(0);
      $dt.found = found;
      $dt.v = v;
      return $dt;
    }
    get is_Res() { return this.$tag === 0; }
    get dtor_found() { return this.found; }
    get dtor_v() { return this.v; }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.Res.Res" + "(" + _dafny.toString(this.found) + ", " + _dafny.toString(this.v) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.found === other.found && _dafny.areEqual(this.v, other.v);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return PolicyVm.Res.create_Res(false, PolicyVm.Value.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Res.Default();
        }
      };
    }
  }

  $module.Tok = class Tok {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_TOpenA() {
      let $dt = new Tok(0);
      return $dt;
    }
    static create_TCloseA() {
      let $dt = new Tok(1);
      return $dt;
    }
    static create_TOpenO() {
      let $dt = new Tok(2);
      return $dt;
    }
    static create_TCloseO() {
      let $dt = new Tok(3);
      return $dt;
    }
    static create_TComma() {
      let $dt = new Tok(4);
      return $dt;
    }
    static create_TColon() {
      let $dt = new Tok(5);
      return $dt;
    }
    static create_TNullT() {
      let $dt = new Tok(6);
      return $dt;
    }
    static create_TTrueT() {
      let $dt = new Tok(7);
      return $dt;
    }
    static create_TFalseT() {
      let $dt = new Tok(8);
      return $dt;
    }
    static create_TNumT(r) {
      let $dt = new Tok(9);
      $dt.r = r;
      return $dt;
    }
    static create_TStrT(s) {
      let $dt = new Tok(10);
      $dt.s = s;
      return $dt;
    }
    get is_TOpenA() { return this.$tag === 0; }
    get is_TCloseA() { return this.$tag === 1; }
    get is_TOpenO() { return this.$tag === 2; }
    get is_TCloseO() { return this.$tag === 3; }
    get is_TComma() { return this.$tag === 4; }
    get is_TColon() { return this.$tag === 5; }
    get is_TNullT() { return this.$tag === 6; }
    get is_TTrueT() { return this.$tag === 7; }
    get is_TFalseT() { return this.$tag === 8; }
    get is_TNumT() { return this.$tag === 9; }
    get is_TStrT() { return this.$tag === 10; }
    get dtor_r() { return this.r; }
    get dtor_s() { return this.s; }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.Tok.TOpenA";
      } else if (this.$tag === 1) {
        return "PolicyVm.Tok.TCloseA";
      } else if (this.$tag === 2) {
        return "PolicyVm.Tok.TOpenO";
      } else if (this.$tag === 3) {
        return "PolicyVm.Tok.TCloseO";
      } else if (this.$tag === 4) {
        return "PolicyVm.Tok.TComma";
      } else if (this.$tag === 5) {
        return "PolicyVm.Tok.TColon";
      } else if (this.$tag === 6) {
        return "PolicyVm.Tok.TNullT";
      } else if (this.$tag === 7) {
        return "PolicyVm.Tok.TTrueT";
      } else if (this.$tag === 8) {
        return "PolicyVm.Tok.TFalseT";
      } else if (this.$tag === 9) {
        return "PolicyVm.Tok.TNumT" + "(" + _dafny.toString(this.r) + ")";
      } else if (this.$tag === 10) {
        return "PolicyVm.Tok.TStrT" + "(" + _dafny.toString(this.s) + ")";
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
        return other.$tag === 9 && _dafny.areEqual(this.r, other.r);
      } else if (this.$tag === 10) {
        return other.$tag === 10 && _dafny.areEqual(this.s, other.s);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return PolicyVm.Tok.create_TOpenA();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Tok.Default();
        }
      };
    }
  }

  $module.GTok = class GTok {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_GLit(c) {
      let $dt = new GTok(0);
      $dt.c = c;
      return $dt;
    }
    static create_GOne() {
      let $dt = new GTok(1);
      return $dt;
    }
    static create_GStar() {
      let $dt = new GTok(2);
      return $dt;
    }
    get is_GLit() { return this.$tag === 0; }
    get is_GOne() { return this.$tag === 1; }
    get is_GStar() { return this.$tag === 2; }
    get dtor_c() { return this.c; }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.GTok.GLit" + "(" + _dafny.toString(this.c) + ")";
      } else if (this.$tag === 1) {
        return "PolicyVm.GTok.GOne";
      } else if (this.$tag === 2) {
        return "PolicyVm.GTok.GStar";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.c === other.c;
      } else if (this.$tag === 1) {
        return other.$tag === 1;
      } else if (this.$tag === 2) {
        return other.$tag === 2;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return PolicyVm.GTok.create_GLit(0);
    }
    static Rtd() {
      return class {
        static get Default() {
          return GTok.Default();
        }
      };
    }
  }

  $module.Rx = class Rx {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Rx(safe, full) {
      let $dt = new Rx(0);
      $dt.safe = safe;
      $dt.full = full;
      return $dt;
    }
    get is_Rx() { return this.$tag === 0; }
    get dtor_safe() { return this.safe; }
    get dtor_full() { return this.full; }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.Rx.Rx" + "(" + _dafny.toString(this.safe) + ", " + _dafny.toString(this.full) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.safe, other.safe) && _dafny.areEqual(this.full, other.full);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return PolicyVm.Rx.create_Rx(function () { return false; }, function () { return PolicyVm.Option.Default(); });
    }
    static Rtd() {
      return class {
        static get Default() {
          return Rx.Default();
        }
      };
    }
  }

  $module.PredRes = class PredRes {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_PredRes(allowed, idx, why) {
      let $dt = new PredRes(0);
      $dt.allowed = allowed;
      $dt.idx = idx;
      $dt.why = why;
      return $dt;
    }
    get is_PredRes() { return this.$tag === 0; }
    get dtor_allowed() { return this.allowed; }
    get dtor_idx() { return this.idx; }
    get dtor_why() { return this.why; }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.PredRes.PredRes" + "(" + _dafny.toString(this.allowed) + ", " + _dafny.toString(this.idx) + ", " + _dafny.toString(this.why) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.allowed === other.allowed && _dafny.areEqual(this.idx, other.idx) && _dafny.areEqual(this.why, other.why);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return PolicyVm.PredRes.create_PredRes(false, _dafny.ZERO, _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return PredRes.Default();
        }
      };
    }
  }

  $module.CavRes = class CavRes {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_CavRes(ok, failed) {
      let $dt = new CavRes(0);
      $dt.ok = ok;
      $dt.failed = failed;
      return $dt;
    }
    get is_CavRes() { return this.$tag === 0; }
    get dtor_ok() { return this.ok; }
    get dtor_failed() { return this.failed; }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.CavRes.CavRes" + "(" + _dafny.toString(this.ok) + ", " + _dafny.toString(this.failed) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.ok === other.ok && _dafny.areEqual(this.failed, other.failed);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return PolicyVm.CavRes.create_CavRes(false, _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return CavRes.Default();
        }
      };
    }
  }

  $module.Thr = class Thr {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Thr(t, proof, opt) {
      let $dt = new Thr(0);
      $dt.t = t;
      $dt.proof = proof;
      $dt.opt = opt;
      return $dt;
    }
    get is_Thr() { return this.$tag === 0; }
    get dtor_t() { return this.t; }
    get dtor_proof() { return this.proof; }
    get dtor_opt() { return this.opt; }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.Thr.Thr" + "(" + _dafny.toString(this.t) + ", " + _dafny.toString(this.proof) + ", " + _dafny.toString(this.opt) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.t, other.t) && _dafny.areEqual(this.proof, other.proof) && this.opt === other.opt;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return PolicyVm.Thr.create_Thr(_dafny.ZERO, _dafny.ZERO, false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Thr.Default();
        }
      };
    }
  }

  $module.Adm = class Adm {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Adm(admit, needStepUp, t, metered) {
      let $dt = new Adm(0);
      $dt.admit = admit;
      $dt.needStepUp = needStepUp;
      $dt.t = t;
      $dt.metered = metered;
      return $dt;
    }
    get is_Adm() { return this.$tag === 0; }
    get dtor_admit() { return this.admit; }
    get dtor_needStepUp() { return this.needStepUp; }
    get dtor_t() { return this.t; }
    get dtor_metered() { return this.metered; }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.Adm.Adm" + "(" + _dafny.toString(this.admit) + ", " + _dafny.toString(this.needStepUp) + ", " + _dafny.toString(this.t) + ", " + _dafny.toString(this.metered) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.admit === other.admit && this.needStepUp === other.needStepUp && _dafny.areEqual(this.t, other.t) && this.metered === other.metered;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return PolicyVm.Adm.create_Adm(false, false, _dafny.ZERO, false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Adm.Default();
        }
      };
    }
  }

  $module.Dec = class Dec {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Dec(release, admit, needStepUp, thr, debit) {
      let $dt = new Dec(0);
      $dt.release = release;
      $dt.admit = admit;
      $dt.needStepUp = needStepUp;
      $dt.thr = thr;
      $dt.debit = debit;
      return $dt;
    }
    get is_Dec() { return this.$tag === 0; }
    get dtor_release() { return this.release; }
    get dtor_admit() { return this.admit; }
    get dtor_needStepUp() { return this.needStepUp; }
    get dtor_thr() { return this.thr; }
    get dtor_debit() { return this.debit; }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.Dec.Dec" + "(" + _dafny.toString(this.release) + ", " + _dafny.toString(this.admit) + ", " + _dafny.toString(this.needStepUp) + ", " + _dafny.toString(this.thr) + ", " + _dafny.toString(this.debit) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.release === other.release && this.admit === other.admit && this.needStepUp === other.needStepUp && _dafny.areEqual(this.thr, other.thr) && this.debit === other.debit;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return PolicyVm.Dec.create_Dec(false, false, false, PolicyVm.Thr.Default(), false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Dec.Default();
        }
      };
    }
  }

  $module.Step = class Step {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_LeakStep(lambda, dt) {
      let $dt = new Step(0);
      $dt.lambda = lambda;
      $dt.dt = dt;
      return $dt;
    }
    static create_RiskStep(r) {
      let $dt = new Step(1);
      $dt.r = r;
      return $dt;
    }
    get is_LeakStep() { return this.$tag === 0; }
    get is_RiskStep() { return this.$tag === 1; }
    get dtor_lambda() { return this.lambda; }
    get dtor_dt() { return this.dt; }
    get dtor_r() { return this.r; }
    toString() {
      if (this.$tag === 0) {
        return "PolicyVm.Step.LeakStep" + "(" + _dafny.toString(this.lambda) + ", " + _dafny.toString(this.dt) + ")";
      } else if (this.$tag === 1) {
        return "PolicyVm.Step.RiskStep" + "(" + _dafny.toString(this.r) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.lambda, other.lambda) && _dafny.areEqual(this.dt, other.dt);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.r, other.r);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return PolicyVm.Step.create_LeakStep(_dafny.BigRational.ZERO, _dafny.BigRational.ZERO);
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
})(); // end of module PolicyVm
let _module = (function() {
  let $module = {};

  return $module;
})(); // end of module _module

// ---- exports (appended by formal/dafny/build-ext.sh) ----
module.exports = { _dafny, PolicyVm };
