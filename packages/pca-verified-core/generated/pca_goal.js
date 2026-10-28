// Dafny program Goal.dfy compiled into JavaScript
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
let GoalIr = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "GoalIr._default";
    }
    _parentTraits() {
      return [];
    }
    static MeetD(a, b) {
      if ((a).isLessThanOrEqualTo(b)) {
        return a;
      } else {
        return b;
      }
    };
    static JoinD(a, b) {
      if ((b).isLessThanOrEqualTo(a)) {
        return a;
      } else {
        return b;
      }
    };
    static AndK(a, b) {
      if ((a).isLessThanOrEqualTo(b)) {
        return a;
      } else {
        return b;
      }
    };
    static OrK(a, b) {
      if ((b).isLessThanOrEqualTo(a)) {
        return a;
      } else {
        return b;
      }
    };
    static NotK(a) {
      return (new BigNumber(2)).minus(a);
    };
    static B2T(b) {
      if (b) {
        return GoalIr.__default.KT;
      } else {
        return GoalIr.__default.KF;
      }
    };
    static DecOfTri(t) {
      return t;
    };
    static AtomV(a) {
      let _source0 = a;
      {
        if (_source0.is_AQ) {
          let _0_q = (_source0).q;
          return GoalIr.V.create_VQ(_0_q);
        }
      }
      {
        let _1_s = (_source0).s;
        return GoalIr.V.create_VS(_1_s);
      }
    };
    static TypeOfV(v) {
      let _source0 = v;
      {
        if (_source0.is_VQ) {
          let _0_q = (_source0).q;
          return GoalIr.Option.create_Some(GoalIr.Ty.create_TyQ((_0_q).dtor_u));
        }
      }
      {
        if (_source0.is_VS) {
          return GoalIr.Option.create_Some(GoalIr.Ty.create_TyS());
        }
      }
      {
        return GoalIr.Option.create_None();
      }
    };
    static ResOk(p, r) {
      let _source0 = p;
      {
        if (_source0.is_PStar) {
          return true;
        }
      }
      {
        let _0_ids = (_source0).ids;
        return _dafny.Seq.contains(_0_ids, r);
      }
    };
    static RelMembers(rels, rel, anchor) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((rels).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.of();
        } else if ((_dafny.areEqual(((rels)[_dafny.ZERO]).dtor_rel, rel)) && (_dafny.areEqual(((rels)[_dafny.ZERO]).dtor_anchor, anchor))) {
          return ((rels)[_dafny.ZERO]).dtor_members;
        } else {
          let _in0 = (rels).slice(_dafny.ONE);
          let _in1 = rel;
          let _in2 = anchor;
          rels = _in0;
          rel = _in1;
          anchor = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static ResolveSel(ont, s) {
      let _source0 = s;
      {
        if (_source0.is_Exact) {
          let _0_id = (_source0).id;
          return GoalIr.ResPat.create_PSet(_dafny.Seq.of(_0_id));
        }
      }
      {
        if (_source0.is_OneOf) {
          let _1_ids = (_source0).ids;
          return GoalIr.ResPat.create_PSet(_1_ids);
        }
      }
      {
        if (_source0.is_Related) {
          let _2_rel = (_source0).rel;
          let _3_anchor = (_source0).anchor;
          return GoalIr.ResPat.create_PSet(GoalIr.__default.RelMembers((ont).dtor_rels, _2_rel, _3_anchor));
        }
      }
      {
        if (_source0.is_AnyRes) {
          return GoalIr.ResPat.create_PStar();
        }
      }
      {
        let _4_ps = (_source0).parts;
        return GoalIr.__default.ResolveParts(ont, _4_ps);
      }
    };
    static ResolvePart(ont, p) {
      let _source0 = p;
      {
        if (_source0.is_PartExact) {
          let _0_id = (_source0).id;
          return GoalIr.ResPat.create_PSet(_dafny.Seq.of(_0_id));
        }
      }
      {
        if (_source0.is_PartOneOf) {
          let _1_ids = (_source0).ids;
          return GoalIr.ResPat.create_PSet(_1_ids);
        }
      }
      {
        let _2_rel = (_source0).rel;
        let _3_anchor = (_source0).anchor;
        return GoalIr.ResPat.create_PSet(GoalIr.__default.RelMembers((ont).dtor_rels, _2_rel, _3_anchor));
      }
    };
    static FilterIn(a, b) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((a).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, ((_dafny.Seq.contains(b, (a)[_dafny.ZERO])) ? (_dafny.Seq.of((a)[_dafny.ZERO])) : (_dafny.Seq.of())));
          let _in0 = (a).slice(_dafny.ONE);
          let _in1 = b;
          a = _in0;
          b = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static InterPat(x, y) {
      let _source0 = x;
      {
        if (_source0.is_PStar) {
          return y;
        }
      }
      {
        let _0_a = (_source0).ids;
        let _source1 = y;
        {
          if (_source1.is_PStar) {
            return x;
          }
        }
        {
          let _1_b = (_source1).ids;
          return GoalIr.ResPat.create_PSet(GoalIr.__default.FilterIn(_0_a, _1_b));
        }
      }
    };
    static ResolveParts(ont, ps) {
      if ((new BigNumber((ps).length)).isEqualTo(_dafny.ZERO)) {
        return GoalIr.ResPat.create_PStar();
      } else {
        return GoalIr.__default.InterPat(GoalIr.__default.ResolvePart(ont, (ps)[_dafny.ZERO]), GoalIr.__default.ResolveParts(ont, (ps).slice(_dafny.ONE)));
      }
    };
    static VerbsOfClass(vs, cls) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((vs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, ((_dafny.areEqual(((vs)[_dafny.ZERO]).dtor_cls, cls)) ? (_dafny.Seq.of(((vs)[_dafny.ZERO]).dtor_verb)) : (_dafny.Seq.of())));
          let _in0 = (vs).slice(_dafny.ONE);
          let _in1 = cls;
          vs = _in0;
          cls = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static ResolveBSel(ont, s) {
      let _source0 = s;
      {
        if (_source0.is_SelGids) {
          let _0_g = (_source0).gids;
          return GoalIr.LSel.create_LSel(_0_g, _dafny.Seq.of());
        }
      }
      {
        let _1_c = (_source0).cls;
        return GoalIr.LSel.create_LSel(_dafny.Seq.of(), GoalIr.__default.VerbsOfClass((ont).dtor_verbs, _1_c));
      }
    };
    static ProhVerbs(ont, t) {
      let _source0 = t;
      {
        if (_source0.is_PVerb) {
          let _0_v = (_source0).verb;
          return _dafny.Seq.of(_0_v);
        }
      }
      {
        let _1_c = (_source0).cls;
        return GoalIr.__default.VerbsOfClass((ont).dtor_verbs, _1_c);
      }
    };
    static EqT(x, y) {
      let _source0 = x;
      {
        if (_source0.is_VQ) {
          let _0_p = (_source0).q;
          let _source1 = y;
          {
            if (_source1.is_VQ) {
              let _1_q = (_source1).q;
              if (_dafny.areEqual((_0_p).dtor_u, (_1_q).dtor_u)) {
                return GoalIr.__default.B2T(((_0_p).dtor_n).isEqualTo((_1_q).dtor_n));
              } else {
                return GoalIr.__default.KU;
              }
            }
          }
          {
            return GoalIr.__default.KU;
          }
        }
      }
      {
        if (_source0.is_VS) {
          let _2_s = (_source0).s;
          let _source2 = y;
          {
            if (_source2.is_VS) {
              let _3_t = (_source2).s;
              return GoalIr.__default.B2T(_dafny.areEqual(_2_s, _3_t));
            }
          }
          {
            return GoalIr.__default.KU;
          }
        }
      }
      {
        return GoalIr.__default.KU;
      }
    };
    static LtT(x, y) {
      let _source0 = x;
      {
        if (_source0.is_VQ) {
          let _0_p = (_source0).q;
          let _source1 = y;
          {
            if (_source1.is_VQ) {
              let _1_q = (_source1).q;
              if (_dafny.areEqual((_0_p).dtor_u, (_1_q).dtor_u)) {
                return GoalIr.__default.B2T(((_0_p).dtor_n).isLessThan((_1_q).dtor_n));
              } else {
                return GoalIr.__default.KU;
              }
            }
          }
          {
            return GoalIr.__default.KU;
          }
        }
      }
      {
        return GoalIr.__default.KU;
      }
    };
    static InT(x, items) {
      if ((new BigNumber((items).length)).isEqualTo(_dafny.ZERO)) {
        return GoalIr.__default.KF;
      } else {
        return GoalIr.__default.OrK(GoalIr.__default.EqT(x, GoalIr.__default.AtomV((items)[_dafny.ZERO])), GoalIr.__default.InT(x, (items).slice(_dafny.ONE)));
      }
    };
    static CmpT(op, x, y) {
      if (((x).is_None) || ((y).is_None)) {
        return GoalIr.__default.KU;
      } else {
        let _source0 = op;
        {
          if (_source0.is_Eq) {
            return GoalIr.__default.EqT((x).dtor_v, (y).dtor_v);
          }
        }
        {
          if (_source0.is_Ne) {
            return GoalIr.__default.NotK(GoalIr.__default.EqT((x).dtor_v, (y).dtor_v));
          }
        }
        {
          if (_source0.is_Lt) {
            return GoalIr.__default.LtT((x).dtor_v, (y).dtor_v);
          }
        }
        {
          if (_source0.is_Gte) {
            return GoalIr.__default.NotK(GoalIr.__default.LtT((x).dtor_v, (y).dtor_v));
          }
        }
        {
          if (_source0.is_Gt) {
            return GoalIr.__default.LtT((y).dtor_v, (x).dtor_v);
          }
        }
        {
          if (_source0.is_Lte) {
            return GoalIr.__default.NotK(GoalIr.__default.LtT((y).dtor_v, (x).dtor_v));
          }
        }
        {
          if (_source0.is_In) {
            let _source1 = (y).dtor_v;
            {
              if (_source1.is_VSet) {
                let _0_items = (_source1).items;
                return GoalIr.__default.InT((x).dtor_v, _0_items);
              }
            }
            {
              return GoalIr.__default.KU;
            }
          }
        }
        {
          return GoalIr.__default.NotK(function () {
            let _source2 = (y).dtor_v;
            {
              if (_source2.is_VSet) {
                let _1_items = (_source2).items;
                return GoalIr.__default.InT((x).dtor_v, _1_items);
              }
            }
            {
              return GoalIr.__default.KU;
            }
          }());
        }
      }
    };
    static NegOp(op) {
      let _source0 = op;
      {
        if (_source0.is_Eq) {
          return GoalIr.Op.create_Ne();
        }
      }
      {
        if (_source0.is_Ne) {
          return GoalIr.Op.create_Eq();
        }
      }
      {
        if (_source0.is_Lt) {
          return GoalIr.Op.create_Gte();
        }
      }
      {
        if (_source0.is_Gte) {
          return GoalIr.Op.create_Lt();
        }
      }
      {
        if (_source0.is_Gt) {
          return GoalIr.Op.create_Lte();
        }
      }
      {
        if (_source0.is_Lte) {
          return GoalIr.Op.create_Gt();
        }
      }
      {
        if (_source0.is_In) {
          return GoalIr.Op.create_Nin();
        }
      }
      {
        return GoalIr.Op.create_In();
      }
    };
    static EvalT(t, a, h) {
      let _source0 = t;
      {
        if (_source0.is_Param) {
          let _0_p = (_source0).path;
          if (((a).dtor_params).contains(_0_p)) {
            return GoalIr.Option.create_Some(((a).dtor_params).get(_0_p));
          } else {
            return GoalIr.Option.create_None();
          }
        }
      }
      {
        if (_source0.is_Lit) {
          let _1_v = (_source0).v;
          return GoalIr.Option.create_Some(_1_v);
        }
      }
      {
        let _2_b = (_source0).bid;
        if (((h).dtor_aggs).contains(_2_b)) {
          return GoalIr.Option.create_Some(GoalIr.V.create_VQ(((h).dtor_aggs).get(_2_b)));
        } else {
          return GoalIr.Option.create_None();
        }
      }
    };
    static EvalC(c, a, h) {
      let _source0 = c;
      {
        if (_source0.is_CTrue) {
          return GoalIr.__default.KT;
        }
      }
      {
        if (_source0.is_Cmp) {
          let _0_op = (_source0).op;
          let _1_l = (_source0).l;
          let _2_r = (_source0).r;
          return GoalIr.__default.CmpT(_0_op, GoalIr.__default.EvalT(_1_l, a, h), GoalIr.__default.EvalT(_2_r, a, h));
        }
      }
      {
        if (_source0.is_And) {
          let _3_x = (_source0).a;
          let _4_y = (_source0).b;
          return GoalIr.__default.AndK(GoalIr.__default.EvalC(_3_x, a, h), GoalIr.__default.EvalC(_4_y, a, h));
        }
      }
      {
        if (_source0.is_Or) {
          let _5_x = (_source0).a;
          let _6_y = (_source0).b;
          return GoalIr.__default.OrK(GoalIr.__default.EvalC(_5_x, a, h), GoalIr.__default.EvalC(_6_y, a, h));
        }
      }
      {
        let _7_x = (_source0).c;
        return GoalIr.__default.NotK(GoalIr.__default.EvalC(_7_x, a, h));
      }
    };
    static StrIn(x, s) {
      return _dafny.Seq.contains(s, x);
    };
    static AppliesL(s, gid, verb) {
      return (_dafny.Seq.contains((s).dtor_gids, gid)) || (_dafny.Seq.contains((s).dtor_verbs, verb));
    };
    static InScope(sc, a, x) {
      let _source0 = sc;
      {
        if (_source0.is_SSession) {
          return _dafny.areEqual((a).dtor_sess, (x).dtor_sess);
        }
      }
      {
        if (_source0.is_SPrincipal) {
          return _dafny.areEqual((a).dtor_prin, (x).dtor_prin);
        }
      }
      {
        if (_source0.is_SOrg) {
          return _dafny.areEqual((a).dtor_org, (x).dtor_org);
        }
      }
      {
        let _0_ag = (_source0).agents;
        return (_dafny.Seq.contains(_0_ag, (a).dtor_agent)) && (_dafny.Seq.contains(_0_ag, (x).dtor_agent));
      }
    };
    static InWindow(w, a, x) {
      let _source0 = w;
      {
        if (_source0.is_WTask) {
          return true;
        }
      }
      {
        if (_source0.is_WLifetime) {
          return true;
        }
      }
      {
        if (_source0.is_WSliding) {
          let _0_ms = (_source0).ms;
          return ((((a).dtor_t).minus(_0_ms)).isLessThan((x).dtor_t)) && (((x).dtor_t).isLessThanOrEqualTo((a).dtor_t));
        }
      }
      {
        let _1_ms = (_source0).ms;
        let _2_t0 = (_source0).t0;
        return ((_dafny.ZERO).isLessThan(_1_ms)) && ((_dafny.EuclideanDivision(((a).dtor_t).minus(_2_t0), _1_ms)).isEqualTo(_dafny.EuclideanDivision(((x).dtor_t).minus(_2_t0), _1_ms)));
      }
    };
    static SelItems(core, s, adms, a) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((adms).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(a));
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, ((((GoalIr.__default.AppliesL(s, ((adms)[_dafny.ZERO]).dtor_gid, (((adms)[_dafny.ZERO]).dtor_act).dtor_verb)) && (GoalIr.__default.InScope((core).dtor_scope, a, ((adms)[_dafny.ZERO]).dtor_act))) && (GoalIr.__default.InWindow((core).dtor_window, a, ((adms)[_dafny.ZERO]).dtor_act))) ? (_dafny.Seq.of(((adms)[_dafny.ZERO]).dtor_act)) : (_dafny.Seq.of())));
          let _in0 = core;
          let _in1 = s;
          let _in2 = (adms).slice(_dafny.ONE);
          let _in3 = a;
          core = _in0;
          s = _in1;
          adms = _in2;
          a = _in3;
          continue TAIL_CALL_START;
        }
      }
    };
    static ItemVals(core, items, h) {
      if ((new BigNumber((items).length)).isEqualTo(_dafny.ZERO)) {
        return GoalIr.Option.create_Some(_dafny.Seq.of());
      } else {
        let _source0 = GoalIr.__default.EvalT((core).dtor_value, (items)[_dafny.ZERO], h);
        {
          if (_source0.is_Some) {
            let v0 = (_source0).v;
            if (v0.is_VQ) {
              let _0_q = (v0).q;
              if (!_dafny.areEqual((_0_q).dtor_u, ((core).dtor_cap).dtor_u)) {
                return GoalIr.Option.create_None();
              } else {
                let _source1 = GoalIr.__default.ItemVals(core, (items).slice(_dafny.ONE), h);
                {
                  if (_source1.is_Some) {
                    let _1_r = (_source1).v;
                    return GoalIr.Option.create_Some(_dafny.Seq.Concat(_dafny.Seq.of((_0_q).dtor_n), _1_r));
                  }
                }
                {
                  return GoalIr.Option.create_None();
                }
              }
            }
          }
        }
        {
          return GoalIr.Option.create_None();
        }
      }
    };
    static SumI(xs) {
      let _0___accumulator = _dafny.ZERO;
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return (_dafny.ZERO).plus(_0___accumulator);
        } else {
          _0___accumulator = (_0___accumulator).plus((xs)[_dafny.ZERO]);
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static MaxI(xs) {
      if ((new BigNumber((xs).length)).isEqualTo(_dafny.ONE)) {
        return (xs)[_dafny.ZERO];
      } else {
        let _0_m = GoalIr.__default.MaxI((xs).slice(_dafny.ONE));
        if ((_0_m).isLessThanOrEqualTo((xs)[_dafny.ZERO])) {
          return (xs)[_dafny.ZERO];
        } else {
          return _0_m;
        }
      }
    };
    static KeyVals(core, items) {
      if ((new BigNumber((items).length)).isEqualTo(_dafny.ZERO)) {
        return GoalIr.Option.create_Some(_dafny.Seq.of());
      } else if (!(((items)[_dafny.ZERO]).dtor_params).contains((core).dtor_key)) {
        return GoalIr.Option.create_None();
      } else {
        let _source0 = GoalIr.__default.KeyVals(core, (items).slice(_dafny.ONE));
        {
          if (_source0.is_Some) {
            let _0_r = (_source0).v;
            return GoalIr.Option.create_Some(_dafny.Seq.Concat(_dafny.Seq.of((((items)[_dafny.ZERO]).dtor_params).get((core).dtor_key)), _0_r));
          }
        }
        {
          return GoalIr.Option.create_None();
        }
      }
    };
    static Dedup(vs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((vs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else if (_dafny.Seq.contains((vs).slice(_dafny.ONE), (vs)[_dafny.ZERO])) {
          let _in0 = (vs).slice(_dafny.ONE);
          vs = _in0;
          continue TAIL_CALL_START;
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of((vs)[_dafny.ZERO]));
          let _in1 = (vs).slice(_dafny.ONE);
          vs = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static Exceeded(core, items, h) {
      let _source0 = (core).dtor_agg;
      {
        if (_source0.is_ACount) {
          return GoalIr.__default.B2T((((core).dtor_cap).dtor_n).isLessThan(new BigNumber((items).length)));
        }
      }
      {
        if (_source0.is_ASum) {
          let _source1 = GoalIr.__default.ItemVals(core, items, h);
          {
            if (_source1.is_Some) {
              let _0_xs = (_source1).v;
              return GoalIr.__default.B2T((((core).dtor_cap).dtor_n).isLessThan(GoalIr.__default.SumI(_0_xs)));
            }
          }
          {
            return GoalIr.__default.KU;
          }
        }
      }
      {
        if (_source0.is_AMax) {
          let _source2 = GoalIr.__default.ItemVals(core, items, h);
          {
            if (_source2.is_Some) {
              let _1_xs = (_source2).v;
              if ((new BigNumber((_1_xs).length)).isEqualTo(_dafny.ZERO)) {
                return GoalIr.__default.KU;
              } else {
                return GoalIr.__default.B2T((((core).dtor_cap).dtor_n).isLessThan(GoalIr.__default.MaxI(_1_xs)));
              }
            }
          }
          {
            return GoalIr.__default.KU;
          }
        }
      }
      {
        let _source3 = GoalIr.__default.KeyVals(core, items);
        {
          if (_source3.is_Some) {
            let _2_vs = (_source3).v;
            return GoalIr.__default.B2T((((core).dtor_cap).dtor_n).isLessThan(new BigNumber((GoalIr.__default.Dedup(_2_vs)).length)));
          }
        }
        {
          return GoalIr.__default.KU;
        }
      }
    };
    static BoundStat(core, s, a, h) {
      let _0_e = GoalIr.__default.Exceeded(core, GoalIr.__default.SelItems(core, s, (h).dtor_adms, a), h);
      if ((_0_e).isEqualTo(GoalIr.__default.KT)) {
        let _source0 = (core).dtor_onExceed;
        {
          if (_source0.is_OnDeny) {
            return GoalIr.__default.Deny;
          }
        }
        {
          return GoalIr.__default.Escalate;
        }
      } else if ((_0_e).isEqualTo(GoalIr.__default.KU)) {
        return GoalIr.__default.Escalate;
      } else {
        return GoalIr.__default.Allow;
      }
    };
    static ValidityDec(v, dg, a, h) {
      if ((((a).dtor_t).isLessThan((v).dtor_notBefore)) || (((v).dtor_notAfter).isLessThan((a).dtor_t))) {
        return GoalIr.__default.Deny;
      } else if ((((_dafny.ZERO).isLessThan((v).dtor_maxIdle)) && ((_dafny.ZERO).isLessThanOrEqualTo((h).dtor_last))) && (((v).dtor_maxIdle).isLessThan(((a).dtor_t).minus((h).dtor_last)))) {
        return GoalIr.__default.Deny;
      } else if ((((a).dtor_depth).isLessThan(_dafny.ZERO)) || (((dg).dtor_maxDepth).isLessThan((a).dtor_depth))) {
        return GoalIr.__default.Deny;
      } else {
        return GoalIr.__default.Allow;
      }
    };
    static DelegOk(dg, gid, a) {
      return (((a).dtor_depth).isEqualTo(_dafny.ZERO)) || (_dafny.Seq.contains((dg).dtor_mayTouch, gid));
    };
    static ProhOne(verbs, res, c, a, h) {
      let _0_m = GoalIr.__default.AndK(GoalIr.__default.B2T(_dafny.Seq.contains(verbs, (a).dtor_verb)), GoalIr.__default.AndK(GoalIr.__default.B2T(GoalIr.__default.ResOk(res, (a).dtor_res)), GoalIr.__default.EvalC(c, a, h)));
      if ((_0_m).isEqualTo(GoalIr.__default.KT)) {
        return GoalIr.__default.Deny;
      } else if ((_0_m).isEqualTo(GoalIr.__default.KU)) {
        return GoalIr.__default.Escalate;
      } else {
        return GoalIr.__default.Allow;
      }
    };
    static ProhDecG(ont, ps, a, h) {
      if ((new BigNumber((ps).length)).isEqualTo(_dafny.ZERO)) {
        return GoalIr.__default.Allow;
      } else {
        return GoalIr.__default.MeetD(GoalIr.__default.ProhOne(GoalIr.__default.ProhVerbs(ont, ((ps)[_dafny.ZERO]).dtor_target), GoalIr.__default.ResolveSel(ont, ((ps)[_dafny.ZERO]).dtor_res), ((ps)[_dafny.ZERO]).dtor_cond, a, h), GoalIr.__default.ProhDecG(ont, (ps).slice(_dafny.ONE), a, h));
      }
    };
    static EscOne(m) {
      if ((m).isEqualTo(GoalIr.__default.KF)) {
        return GoalIr.__default.Allow;
      } else {
        return GoalIr.__default.Escalate;
      }
    };
    static EscDecG(cs, a, h) {
      if ((new BigNumber((cs).length)).isEqualTo(_dafny.ZERO)) {
        return GoalIr.__default.Allow;
      } else {
        return GoalIr.__default.MeetD(GoalIr.__default.EscOne(GoalIr.__default.EvalC((cs)[_dafny.ZERO], a, h)), GoalIr.__default.EscDecG((cs).slice(_dafny.ONE), a, h));
      }
    };
    static BoundsDecG(ont, bs, gid, a, h) {
      if ((new BigNumber((bs).length)).isEqualTo(_dafny.ZERO)) {
        return GoalIr.__default.Allow;
      } else {
        let _0_s = GoalIr.__default.ResolveBSel(ont, ((bs)[_dafny.ZERO]).dtor_sel);
        return GoalIr.__default.MeetD(((GoalIr.__default.AppliesL(_0_s, gid, (a).dtor_verb)) ? (GoalIr.__default.BoundStat(((bs)[_dafny.ZERO]).dtor_core, _0_s, a, h)) : (GoalIr.__default.Allow)), GoalIr.__default.BoundsDecG(ont, (bs).slice(_dafny.ONE), gid, a, h));
      }
    };
    static GrantMatch(ont, g, dg, a, h) {
      return GoalIr.__default.AndK(GoalIr.__default.B2T((_dafny.areEqual((a).dtor_verb, (g).dtor_verb)) && (GoalIr.__default.DelegOk(dg, (g).dtor_gid, a))), GoalIr.__default.AndK(GoalIr.__default.B2T(GoalIr.__default.ResOk(GoalIr.__default.ResolveSel(ont, (g).dtor_res), (a).dtor_res)), GoalIr.__default.EvalC((g).dtor_cond, a, h)));
    };
    static GrantDecG(ont, g, gr, a, h) {
      return GoalIr.__default.MeetD(GoalIr.__default.DecOfTri(GoalIr.__default.GrantMatch(ont, gr, (g).dtor_deleg, a, h)), GoalIr.__default.BoundsDecG(ont, (g).dtor_bounds, (gr).dtor_gid, a, h));
    };
    static GrantsDecG(ont, g, gs, a, h) {
      if ((new BigNumber((gs).length)).isEqualTo(_dafny.ZERO)) {
        return GoalIr.__default.Deny;
      } else {
        return GoalIr.__default.JoinD(GoalIr.__default.GrantDecG(ont, g, (gs)[_dafny.ZERO], a, h), GoalIr.__default.GrantsDecG(ont, g, (gs).slice(_dafny.ONE), a, h));
      }
    };
    static DG(ont, g, a, h) {
      return GoalIr.__default.MeetD(GoalIr.__default.ValidityDec((g).dtor_validity, (g).dtor_deleg, a, h), GoalIr.__default.MeetD(GoalIr.__default.ProhDecG(ont, (g).dtor_prohibits, a, h), GoalIr.__default.MeetD(GoalIr.__default.EscDecG((g).dtor_escalateOn, a, h), GoalIr.__default.GrantsDecG(ont, g, (g).dtor_grants, a, h))));
    };
    static StrLt(a, b) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((b).length)).isEqualTo(_dafny.ZERO)) {
          return false;
        } else if ((new BigNumber((a).length)).isEqualTo(_dafny.ZERO)) {
          return true;
        } else if (!_dafny.areEqual((a)[_dafny.ZERO], (b)[_dafny.ZERO])) {
          return (new BigNumber(((a)[_dafny.ZERO]).value)).isLessThan(new BigNumber(((b)[_dafny.ZERO]).value));
        } else {
          let _in0 = (a).slice(_dafny.ONE);
          let _in1 = (b).slice(_dafny.ONE);
          a = _in0;
          b = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static StrictlySorted(xs) {
      return ((new BigNumber((xs).length)).isLessThanOrEqualTo(_dafny.ONE)) || ((GoalIr.__default.StrLt((xs)[_dafny.ZERO], (xs)[_dafny.ONE])) && (GoalIr.__default.StrictlySorted((xs).slice(_dafny.ONE))));
    };
    static UnitOk(u) {
      let _source0 = u;
      {
        if (_source0.is_UMoney) {
          let _0_c = (_source0).ccy;
          return (_dafny.ZERO).isLessThan(new BigNumber((_0_c).length));
        }
      }
      {
        return true;
      }
    };
    static TyOk(t) {
      let _source0 = t;
      {
        if (_source0.is_TyQ) {
          let _0_u = (_source0).u;
          return GoalIr.__default.UnitOk(_0_u);
        }
      }
      {
        return true;
      }
    };
    static VOk(v) {
      let _source0 = v;
      {
        if (_source0.is_VQ) {
          let _0_q = (_source0).q;
          return GoalIr.__default.UnitOk((_0_q).dtor_u);
        }
      }
      {
        if (_source0.is_VS) {
          return true;
        }
      }
      {
        let _1_items = (_source0).items;
        return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((_1_items).length)), true, function (_forall_var_0) {
          let _2_i = _forall_var_0;
          return !(((_dafny.ZERO).isLessThanOrEqualTo(_2_i)) && ((_2_i).isLessThan(new BigNumber((_1_items).length)))) || (function () {
            let _source1 = (_1_items)[_2_i];
            {
              if (_source1.is_AQ) {
                let _3_q = (_source1).q;
                return GoalIr.__default.UnitOk((_3_q).dtor_u);
              }
            }
            {
              return true;
            }
          }());
        });
      }
    };
    static TypeOfTerm(t) {
      let _source0 = t;
      {
        if (_source0.is_Param) {
          let _0_ty = (_source0).ty;
          return GoalIr.Option.create_Some(_0_ty);
        }
      }
      {
        if (_source0.is_Lit) {
          let _1_v = (_source0).v;
          return GoalIr.__default.TypeOfV(_1_v);
        }
      }
      {
        let _2_u = (_source0).u;
        return GoalIr.Option.create_Some(GoalIr.Ty.create_TyQ(_2_u));
      }
    };
    static TermOk(t) {
      let _source0 = t;
      {
        if (_source0.is_Param) {
          let _0_p = (_source0).path;
          let _1_ty = (_source0).ty;
          return ((_dafny.ZERO).isLessThan(new BigNumber((_0_p).length))) && (GoalIr.__default.TyOk(_1_ty));
        }
      }
      {
        if (_source0.is_Lit) {
          let _2_v = (_source0).v;
          return GoalIr.__default.VOk(_2_v);
        }
      }
      {
        let _3_b = (_source0).bid;
        let _4_u = (_source0).u;
        return ((_dafny.ZERO).isLessThan(new BigNumber((_3_b).length))) && (GoalIr.__default.UnitOk(_4_u));
      }
    };
    static AllOfTy(items, ty) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((items).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((items).length)))) || (_dafny.areEqual(GoalIr.__default.TypeOfV(GoalIr.__default.AtomV((items)[_0_i])), GoalIr.Option.create_Some(ty)));
      });
    };
    static CmpTyped(op, l, r) {
      return (((GoalIr.__default.TermOk(l)) && (GoalIr.__default.TermOk(r))) && ((GoalIr.__default.TypeOfTerm(l)).is_Some)) && (function () {
        let _source0 = op;
        {
          if (_source0.is_Eq) {
            return _dafny.areEqual(GoalIr.__default.TypeOfTerm(l), GoalIr.__default.TypeOfTerm(r));
          }
        }
        {
          if (_source0.is_Ne) {
            return _dafny.areEqual(GoalIr.__default.TypeOfTerm(l), GoalIr.__default.TypeOfTerm(r));
          }
        }
        {
          if (_source0.is_Lt) {
            return (_dafny.areEqual(GoalIr.__default.TypeOfTerm(l), GoalIr.__default.TypeOfTerm(r))) && (((GoalIr.__default.TypeOfTerm(l)).dtor_v).is_TyQ);
          }
        }
        {
          if (_source0.is_Lte) {
            return (_dafny.areEqual(GoalIr.__default.TypeOfTerm(l), GoalIr.__default.TypeOfTerm(r))) && (((GoalIr.__default.TypeOfTerm(l)).dtor_v).is_TyQ);
          }
        }
        {
          if (_source0.is_Gt) {
            return (_dafny.areEqual(GoalIr.__default.TypeOfTerm(l), GoalIr.__default.TypeOfTerm(r))) && (((GoalIr.__default.TypeOfTerm(l)).dtor_v).is_TyQ);
          }
        }
        {
          if (_source0.is_Gte) {
            return (_dafny.areEqual(GoalIr.__default.TypeOfTerm(l), GoalIr.__default.TypeOfTerm(r))) && (((GoalIr.__default.TypeOfTerm(l)).dtor_v).is_TyQ);
          }
        }
        {
          if (_source0.is_In) {
            return (((r).is_Lit) && (((r).dtor_v).is_VSet)) && (GoalIr.__default.AllOfTy(((r).dtor_v).dtor_items, (GoalIr.__default.TypeOfTerm(l)).dtor_v));
          }
        }
        {
          return (((r).is_Lit) && (((r).dtor_v).is_VSet)) && (GoalIr.__default.AllOfTy(((r).dtor_v).dtor_items, (GoalIr.__default.TypeOfTerm(l)).dtor_v));
        }
      }());
    };
    static CondTyped(c, ok) {
      let _source0 = c;
      {
        if (_source0.is_CTrue) {
          return true;
        }
      }
      {
        if (_source0.is_Cmp) {
          let _0_op = (_source0).op;
          let _1_l = (_source0).l;
          let _2_r = (_source0).r;
          return ((GoalIr.__default.CmpTyped(_0_op, _1_l, _2_r)) && (GoalIr.__default.ParamsOk(_1_l, ok))) && (GoalIr.__default.ParamsOk(_2_r, ok));
        }
      }
      {
        if (_source0.is_And) {
          let _3_x = (_source0).a;
          let _4_y = (_source0).b;
          return (GoalIr.__default.CondTyped(_3_x, ok)) && (GoalIr.__default.CondTyped(_4_y, ok));
        }
      }
      {
        if (_source0.is_Or) {
          let _5_x = (_source0).a;
          let _6_y = (_source0).b;
          return (GoalIr.__default.CondTyped(_5_x, ok)) && (GoalIr.__default.CondTyped(_6_y, ok));
        }
      }
      {
        let _7_x = (_source0).c;
        return GoalIr.__default.CondTyped(_7_x, ok);
      }
    };
    static ParamsOk(t, ok) {
      let _source0 = t;
      {
        if (_source0.is_Param) {
          let _0_p = (_source0).path;
          let _1_ty = (_source0).ty;
          return (ok)(_0_p, _1_ty);
        }
      }
      {
        return true;
      }
    };
    static FindDecl(vs, verb) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((vs).length)).isEqualTo(_dafny.ZERO)) {
          return GoalIr.Option.create_None();
        } else if (_dafny.areEqual(((vs)[_dafny.ZERO]).dtor_verb, verb)) {
          return GoalIr.Option.create_Some((vs)[_dafny.ZERO]);
        } else {
          let _in0 = (vs).slice(_dafny.ONE);
          let _in1 = verb;
          vs = _in0;
          verb = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static HasParam(ps, p, ty) {
      return _dafny.Seq.contains(ps, GoalIr.ParamDecl.create_ParamDecl(p, ty));
    };
    static DeclaredFor(ont, verbs, p, ty) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((verbs).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((verbs).length)))) || (((GoalIr.__default.FindDecl((ont).dtor_verbs, (verbs)[_0_i])).is_Some) && (GoalIr.__default.HasParam(((GoalIr.__default.FindDecl((ont).dtor_verbs, (verbs)[_0_i])).dtor_v).dtor_params, p, ty)));
      });
    };
    static NoConflictP(ps, p, ty) {
      return ((new BigNumber((ps).length)).isEqualTo(_dafny.ZERO)) || (((!_dafny.areEqual(((ps)[_dafny.ZERO]).dtor_path, p)) || (_dafny.areEqual(((ps)[_dafny.ZERO]).dtor_ty, ty))) && (GoalIr.__default.NoConflictP((ps).slice(_dafny.ONE), p, ty)));
    };
    static NoConflict(vs, p, ty) {
      return ((new BigNumber((vs).length)).isEqualTo(_dafny.ZERO)) || ((GoalIr.__default.NoConflictP(((vs)[_dafny.ZERO]).dtor_params, p, ty)) && (GoalIr.__default.NoConflict((vs).slice(_dafny.ONE), p, ty)));
    };
    static ResSelOk(ont, s) {
      let _source0 = s;
      {
        if (_source0.is_Exact) {
          let _0_id = (_source0).id;
          return (_dafny.ZERO).isLessThan(new BigNumber((_0_id).length));
        }
      }
      {
        if (_source0.is_OneOf) {
          let _1_ids = (_source0).ids;
          return (_dafny.ZERO).isLessThan(new BigNumber((_1_ids).length));
        }
      }
      {
        if (_source0.is_Related) {
          let _2_rel = (_source0).rel;
          let _3_anchor = (_source0).anchor;
          return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((ont).dtor_rels).length)), false, function (_exists_var_0) {
            let _4_i = _exists_var_0;
            return ((((_dafny.ZERO).isLessThanOrEqualTo(_4_i)) && ((_4_i).isLessThan(new BigNumber(((ont).dtor_rels).length)))) && (_dafny.areEqual((((ont).dtor_rels)[_4_i]).dtor_rel, _2_rel))) && (_dafny.areEqual((((ont).dtor_rels)[_4_i]).dtor_anchor, _3_anchor));
          });
        }
      }
      {
        if (_source0.is_AnyRes) {
          return true;
        }
      }
      {
        let _5_ps = (_source0).parts;
        return ((new BigNumber(2)).isLessThanOrEqualTo(new BigNumber((_5_ps).length))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((_5_ps).length)), true, function (_forall_var_0) {
          let _6_i = _forall_var_0;
          return !(((_dafny.ZERO).isLessThanOrEqualTo(_6_i)) && ((_6_i).isLessThan(new BigNumber((_5_ps).length)))) || (GoalIr.__default.PartOk(ont, (_5_ps)[_6_i]));
        }));
      }
    };
    static PartOk(ont, p) {
      let _source0 = p;
      {
        if (_source0.is_PartExact) {
          let _0_id = (_source0).id;
          return (_dafny.ZERO).isLessThan(new BigNumber((_0_id).length));
        }
      }
      {
        if (_source0.is_PartOneOf) {
          let _1_ids = (_source0).ids;
          return (_dafny.ZERO).isLessThan(new BigNumber((_1_ids).length));
        }
      }
      {
        let _2_rel = (_source0).rel;
        let _3_anchor = (_source0).anchor;
        return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((ont).dtor_rels).length)), false, function (_exists_var_0) {
          let _4_i = _exists_var_0;
          return ((((_dafny.ZERO).isLessThanOrEqualTo(_4_i)) && ((_4_i).isLessThan(new BigNumber(((ont).dtor_rels).length)))) && (_dafny.areEqual((((ont).dtor_rels)[_4_i]).dtor_rel, _2_rel))) && (_dafny.areEqual((((ont).dtor_rels)[_4_i]).dtor_anchor, _3_anchor));
        });
      }
    };
    static GrantOk(ont, g, gr) {
      return (((((_dafny.ZERO).isLessThan(new BigNumber(((gr).dtor_gid).length))) && ((GoalIr.__default.FindDecl((ont).dtor_verbs, (gr).dtor_verb)).is_Some)) && (GoalIr.__default.ResSelOk(ont, (gr).dtor_res))) && (!(((gr).dtor_res).is_AnyRes) || (_dafny.Seq.contains((g).dtor_wildcardAck, (gr).dtor_gid)))) && (GoalIr.__default.CondTyped((gr).dtor_cond, ((_0_ont, _1_gr) => function (_2_p, _3_ty) {
        return GoalIr.__default.DeclaredFor(_0_ont, _dafny.Seq.of((_1_gr).dtor_verb), _2_p, _3_ty);
      })(ont, gr)));
    };
    static ProhibitOk(ont, p) {
      return ((((_dafny.ZERO).isLessThan(new BigNumber(((p).dtor_pid).length))) && (GoalIr.__default.ResSelOk(ont, (p).dtor_res))) && (function () {
        let _source0 = (p).dtor_target;
        {
          if (_source0.is_PVerb) {
            let _0_v = (_source0).verb;
            return (GoalIr.__default.FindDecl((ont).dtor_verbs, _0_v)).is_Some;
          }
        }
        {
          let _1_c = (_source0).cls;
          return ((_dafny.ZERO).isLessThan(new BigNumber((_1_c).length))) && ((_dafny.ZERO).isLessThan(new BigNumber((GoalIr.__default.VerbsOfClass((ont).dtor_verbs, _1_c)).length)));
        }
      }())) && (GoalIr.__default.CondTyped((p).dtor_cond, ((_2_ont, _3_p) => function (_4_q, _5_ty) {
        return GoalIr.__default.DeclaredFor(_2_ont, GoalIr.__default.ProhVerbs(_2_ont, (_3_p).dtor_target), _4_q, _5_ty);
      })(ont, p)));
    };
    static WindowOk(w) {
      let _source0 = w;
      {
        if (_source0.is_WSliding) {
          let _0_ms = (_source0).ms;
          return (_dafny.ZERO).isLessThan(_0_ms);
        }
      }
      {
        if (_source0.is_WPeriod) {
          let _1_ms = (_source0).ms;
          return (_dafny.ZERO).isLessThan(_1_ms);
        }
      }
      {
        return true;
      }
    };
    static ScopeOk(s) {
      let _source0 = s;
      {
        if (_source0.is_SFleet) {
          let _0_ag = (_source0).agents;
          return (_dafny.ZERO).isLessThan(new BigNumber((_0_ag).length));
        }
      }
      {
        return true;
      }
    };
    static BoundOk(ont, g, b) {
      return ((((((((_dafny.ZERO).isLessThan(new BigNumber(((b).dtor_bid).length))) && (GoalIr.__default.TermOk(((b).dtor_core).dtor_value))) && (GoalIr.__default.UnitOk((((b).dtor_core).dtor_cap).dtor_u))) && ((_dafny.ZERO).isLessThanOrEqualTo((((b).dtor_core).dtor_cap).dtor_n))) && (GoalIr.__default.WindowOk(((b).dtor_core).dtor_window))) && (GoalIr.__default.ScopeOk(((b).dtor_core).dtor_scope))) && (function () {
        let _source0 = (b).dtor_sel;
        {
          if (_source0.is_SelGids) {
            let _0_gids = (_source0).gids;
            return ((_dafny.ZERO).isLessThan(new BigNumber((_0_gids).length))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((_0_gids).length)), true, function (_forall_var_0) {
              let _1_i = _forall_var_0;
              return !(((_dafny.ZERO).isLessThanOrEqualTo(_1_i)) && ((_1_i).isLessThan(new BigNumber((_0_gids).length)))) || (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((g).dtor_grants).length)), false, function (_exists_var_0) {
                let _2_j = _exists_var_0;
                return (((_dafny.ZERO).isLessThanOrEqualTo(_2_j)) && ((_2_j).isLessThan(new BigNumber(((g).dtor_grants).length)))) && (_dafny.areEqual((((g).dtor_grants)[_2_j]).dtor_gid, (_0_gids)[_1_i]));
              }));
            }));
          }
        }
        {
          let _3_c = (_source0).cls;
          return (_dafny.ZERO).isLessThan(new BigNumber((_3_c).length));
        }
      }())) && (function () {
        let _source1 = ((b).dtor_core).dtor_agg;
        {
          if (_source1.is_ACount) {
            return _dafny.areEqual((((b).dtor_core).dtor_cap).dtor_u, GoalIr.Unit.create_UCount());
          }
        }
        {
          if (_source1.is_ASum) {
            return _dafny.areEqual(GoalIr.__default.TypeOfTerm(((b).dtor_core).dtor_value), GoalIr.Option.create_Some(GoalIr.Ty.create_TyQ((((b).dtor_core).dtor_cap).dtor_u)));
          }
        }
        {
          if (_source1.is_AMax) {
            return _dafny.areEqual(GoalIr.__default.TypeOfTerm(((b).dtor_core).dtor_value), GoalIr.Option.create_Some(GoalIr.Ty.create_TyQ((((b).dtor_core).dtor_cap).dtor_u)));
          }
        }
        {
          return (_dafny.areEqual((((b).dtor_core).dtor_cap).dtor_u, GoalIr.Unit.create_UCount())) && ((_dafny.ZERO).isLessThan(new BigNumber((((b).dtor_core).dtor_key).length)));
        }
      }());
    };
    static ValidityOk(v, dg, g) {
      return ((((((v).dtor_notBefore).isLessThanOrEqualTo((v).dtor_notAfter)) && ((_dafny.ZERO).isLessThanOrEqualTo((v).dtor_maxIdle))) && (((_dafny.ZERO).isLessThanOrEqualTo((dg).dtor_maxDepth)) && (((dg).dtor_maxDepth).isLessThanOrEqualTo(new BigNumber(16))))) && ((dg).dtor_narrowOnly)) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((dg).dtor_mayTouch).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber(((dg).dtor_mayTouch).length)))) || (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((g).dtor_grants).length)), false, function (_exists_var_0) {
          let _1_j = _exists_var_0;
          return (((_dafny.ZERO).isLessThanOrEqualTo(_1_j)) && ((_1_j).isLessThan(new BigNumber(((g).dtor_grants).length)))) && (_dafny.areEqual((((g).dtor_grants)[_1_j]).dtor_gid, ((dg).dtor_mayTouch)[_0_i]));
        }));
      }));
    };
    static HoleOk(g, h) {
      return ((_dafny.ZERO).isLessThan(new BigNumber(((h).dtor_hid).length))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((h).dtor_affects).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber(((h).dtor_affects).length)))) || (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((g).dtor_grants).length)), false, function (_exists_var_0) {
          let _1_j = _exists_var_0;
          return (((_dafny.ZERO).isLessThanOrEqualTo(_1_j)) && ((_1_j).isLessThan(new BigNumber(((g).dtor_grants).length)))) && (_dafny.areEqual((((g).dtor_grants)[_1_j]).dtor_gid, ((h).dtor_affects)[_0_i]));
        }));
      }));
    };
    static Gids(gs) {
      return _dafny.Seq.Create(new BigNumber((gs).length), ((_0_gs) => function (_1_i) {
        return ((_0_gs)[_1_i]).dtor_gid;
      })(gs));
    };
    static Pids(ps) {
      return _dafny.Seq.Create(new BigNumber((ps).length), ((_0_ps) => function (_1_i) {
        return ((_0_ps)[_1_i]).dtor_pid;
      })(ps));
    };
    static Bids(bs) {
      return _dafny.Seq.Create(new BigNumber((bs).length), ((_0_bs) => function (_1_i) {
        return ((_0_bs)[_1_i]).dtor_bid;
      })(bs));
    };
    static Hids(hs) {
      return _dafny.Seq.Create(new BigNumber((hs).length), ((_0_hs) => function (_1_i) {
        return ((_0_hs)[_1_i]).dtor_hid;
      })(hs));
    };
    static EscsTyped(ont, g) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((g).dtor_escalateOn).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber(((g).dtor_escalateOn).length)))) || (GoalIr.__default.CondTyped(((g).dtor_escalateOn)[_0_i], ((_1_ont) => function (_2_p, _3_ty) {
          return GoalIr.__default.NoConflict((_1_ont).dtor_verbs, _2_p, _3_ty);
        })(ont)));
      });
    };
    static Sorted4(g) {
      return (((GoalIr.__default.StrictlySorted(GoalIr.__default.Gids((g).dtor_grants))) && (GoalIr.__default.StrictlySorted(GoalIr.__default.Pids((g).dtor_prohibits)))) && (GoalIr.__default.StrictlySorted(GoalIr.__default.Bids((g).dtor_bounds)))) && (GoalIr.__default.StrictlySorted(GoalIr.__default.Hids((g).dtor_holes)));
    };
    static IsWellTyped(ont, g) {
      return ((((((GoalIr.__default.Sorted4(g)) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((g).dtor_grants).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber(((g).dtor_grants).length)))) || (GoalIr.__default.GrantOk(ont, g, ((g).dtor_grants)[_0_i]));
      }))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((g).dtor_prohibits).length)), true, function (_forall_var_1) {
        let _1_i = _forall_var_1;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_1_i)) && ((_1_i).isLessThan(new BigNumber(((g).dtor_prohibits).length)))) || (GoalIr.__default.ProhibitOk(ont, ((g).dtor_prohibits)[_1_i]));
      }))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((g).dtor_bounds).length)), true, function (_forall_var_2) {
        let _2_i = _forall_var_2;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_2_i)) && ((_2_i).isLessThan(new BigNumber(((g).dtor_bounds).length)))) || (GoalIr.__default.BoundOk(ont, g, ((g).dtor_bounds)[_2_i]));
      }))) && (GoalIr.__default.EscsTyped(ont, g))) && (GoalIr.__default.ValidityOk((g).dtor_validity, (g).dtor_deleg, g))) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((g).dtor_holes).length)), true, function (_forall_var_3) {
        let _3_i = _forall_var_3;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_3_i)) && ((_3_i).isLessThan(new BigNumber(((g).dtor_holes).length)))) || (GoalIr.__default.HoleOk(g, ((g).dtor_holes)[_3_i]));
      }));
    };
    static Signable(ont, g) {
      return (GoalIr.__default.IsWellTyped(ont, g)) && ((new BigNumber(((g).dtor_holes).length)).isEqualTo(_dafny.ZERO));
    };
    static get Deny() {
      return _dafny.ZERO;
    };
    static get Escalate() {
      return _dafny.ONE;
    };
    static get Allow() {
      return new BigNumber(2);
    };
    static get KF() {
      return _dafny.ZERO;
    };
    static get KU() {
      return _dafny.ONE;
    };
    static get KT() {
      return new BigNumber(2);
    };
  };

  $module.Dec = class Dec {
    constructor () {
    }
    static get Default() {
      return _dafny.ZERO;
    }
    static _Is(__source) {
      let _0_d = (__source);
      return ((_dafny.ZERO).isLessThanOrEqualTo(_0_d)) && ((_0_d).isLessThanOrEqualTo(new BigNumber(2)));
    }
  };

  $module.Tri = class Tri {
    constructor () {
    }
    static get Default() {
      return _dafny.ZERO;
    }
    static _Is(__source) {
      let _1_t = (__source);
      return ((_dafny.ZERO).isLessThanOrEqualTo(_1_t)) && ((_1_t).isLessThanOrEqualTo(new BigNumber(2)));
    }
  };

  $module.Unit = class Unit {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_UMoney(ccy) {
      let $dt = new Unit(0);
      $dt.ccy = ccy;
      return $dt;
    }
    static create_UCount() {
      let $dt = new Unit(1);
      return $dt;
    }
    static create_UDuration() {
      let $dt = new Unit(2);
      return $dt;
    }
    static create_UInstant() {
      let $dt = new Unit(3);
      return $dt;
    }
    static create_UBytes() {
      let $dt = new Unit(4);
      return $dt;
    }
    static create_URatio() {
      let $dt = new Unit(5);
      return $dt;
    }
    get is_UMoney() { return this.$tag === 0; }
    get is_UCount() { return this.$tag === 1; }
    get is_UDuration() { return this.$tag === 2; }
    get is_UInstant() { return this.$tag === 3; }
    get is_UBytes() { return this.$tag === 4; }
    get is_URatio() { return this.$tag === 5; }
    get dtor_ccy() { return this.ccy; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Unit.UMoney" + "(" + this.ccy.toVerbatimString(true) + ")";
      } else if (this.$tag === 1) {
        return "GoalIr.Unit.UCount";
      } else if (this.$tag === 2) {
        return "GoalIr.Unit.UDuration";
      } else if (this.$tag === 3) {
        return "GoalIr.Unit.UInstant";
      } else if (this.$tag === 4) {
        return "GoalIr.Unit.UBytes";
      } else if (this.$tag === 5) {
        return "GoalIr.Unit.URatio";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.ccy, other.ccy);
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
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Unit.create_UMoney(_dafny.Seq.UnicodeFromString(""));
    }
    static Rtd() {
      return class {
        static get Default() {
          return Unit.Default();
        }
      };
    }
  }

  $module.Q = class Q {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Q(u, n) {
      let $dt = new Q(0);
      $dt.u = u;
      $dt.n = n;
      return $dt;
    }
    get is_Q() { return this.$tag === 0; }
    get dtor_u() { return this.u; }
    get dtor_n() { return this.n; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Q.Q" + "(" + _dafny.toString(this.u) + ", " + _dafny.toString(this.n) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.u, other.u) && _dafny.areEqual(this.n, other.n);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Q.create_Q(GoalIr.Unit.Default(), _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Q.Default();
        }
      };
    }
  }

  $module.Atom = class Atom {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_AQ(q) {
      let $dt = new Atom(0);
      $dt.q = q;
      return $dt;
    }
    static create_AS(s) {
      let $dt = new Atom(1);
      $dt.s = s;
      return $dt;
    }
    get is_AQ() { return this.$tag === 0; }
    get is_AS() { return this.$tag === 1; }
    get dtor_q() { return this.q; }
    get dtor_s() { return this.s; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Atom.AQ" + "(" + _dafny.toString(this.q) + ")";
      } else if (this.$tag === 1) {
        return "GoalIr.Atom.AS" + "(" + this.s.toVerbatimString(true) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.q, other.q);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.s, other.s);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Atom.create_AQ(GoalIr.Q.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Atom.Default();
        }
      };
    }
  }

  $module.V = class V {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_VQ(q) {
      let $dt = new V(0);
      $dt.q = q;
      return $dt;
    }
    static create_VS(s) {
      let $dt = new V(1);
      $dt.s = s;
      return $dt;
    }
    static create_VSet(items) {
      let $dt = new V(2);
      $dt.items = items;
      return $dt;
    }
    get is_VQ() { return this.$tag === 0; }
    get is_VS() { return this.$tag === 1; }
    get is_VSet() { return this.$tag === 2; }
    get dtor_q() { return this.q; }
    get dtor_s() { return this.s; }
    get dtor_items() { return this.items; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.V.VQ" + "(" + _dafny.toString(this.q) + ")";
      } else if (this.$tag === 1) {
        return "GoalIr.V.VS" + "(" + this.s.toVerbatimString(true) + ")";
      } else if (this.$tag === 2) {
        return "GoalIr.V.VSet" + "(" + _dafny.toString(this.items) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.q, other.q);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.s, other.s);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.items, other.items);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.V.create_VQ(GoalIr.Q.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return V.Default();
        }
      };
    }
  }

  $module.Ty = class Ty {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_TyQ(u) {
      let $dt = new Ty(0);
      $dt.u = u;
      return $dt;
    }
    static create_TyS() {
      let $dt = new Ty(1);
      return $dt;
    }
    get is_TyQ() { return this.$tag === 0; }
    get is_TyS() { return this.$tag === 1; }
    get dtor_u() { return this.u; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Ty.TyQ" + "(" + _dafny.toString(this.u) + ")";
      } else if (this.$tag === 1) {
        return "GoalIr.Ty.TyS";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.u, other.u);
      } else if (this.$tag === 1) {
        return other.$tag === 1;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Ty.create_TyQ(GoalIr.Unit.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Ty.Default();
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
        return "GoalIr.Option.None";
      } else if (this.$tag === 1) {
        return "GoalIr.Option.Some" + "(" + _dafny.toString(this.v) + ")";
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
      return GoalIr.Option.create_None();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Option.Default();
        }
      };
    }
  }

  $module.Term = class Term {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Param(path, ty) {
      let $dt = new Term(0);
      $dt.path = path;
      $dt.ty = ty;
      return $dt;
    }
    static create_Lit(v) {
      let $dt = new Term(1);
      $dt.v = v;
      return $dt;
    }
    static create_HistAgg(bid, u) {
      let $dt = new Term(2);
      $dt.bid = bid;
      $dt.u = u;
      return $dt;
    }
    get is_Param() { return this.$tag === 0; }
    get is_Lit() { return this.$tag === 1; }
    get is_HistAgg() { return this.$tag === 2; }
    get dtor_path() { return this.path; }
    get dtor_ty() { return this.ty; }
    get dtor_v() { return this.v; }
    get dtor_bid() { return this.bid; }
    get dtor_u() { return this.u; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Term.Param" + "(" + this.path.toVerbatimString(true) + ", " + _dafny.toString(this.ty) + ")";
      } else if (this.$tag === 1) {
        return "GoalIr.Term.Lit" + "(" + _dafny.toString(this.v) + ")";
      } else if (this.$tag === 2) {
        return "GoalIr.Term.HistAgg" + "(" + this.bid.toVerbatimString(true) + ", " + _dafny.toString(this.u) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.path, other.path) && _dafny.areEqual(this.ty, other.ty);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.v, other.v);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.bid, other.bid) && _dafny.areEqual(this.u, other.u);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Term.create_Param(_dafny.Seq.UnicodeFromString(""), GoalIr.Ty.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Term.Default();
        }
      };
    }
  }

  $module.Op = class Op {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Eq() {
      let $dt = new Op(0);
      return $dt;
    }
    static create_Ne() {
      let $dt = new Op(1);
      return $dt;
    }
    static create_Lt() {
      let $dt = new Op(2);
      return $dt;
    }
    static create_Lte() {
      let $dt = new Op(3);
      return $dt;
    }
    static create_Gt() {
      let $dt = new Op(4);
      return $dt;
    }
    static create_Gte() {
      let $dt = new Op(5);
      return $dt;
    }
    static create_In() {
      let $dt = new Op(6);
      return $dt;
    }
    static create_Nin() {
      let $dt = new Op(7);
      return $dt;
    }
    get is_Eq() { return this.$tag === 0; }
    get is_Ne() { return this.$tag === 1; }
    get is_Lt() { return this.$tag === 2; }
    get is_Lte() { return this.$tag === 3; }
    get is_Gt() { return this.$tag === 4; }
    get is_Gte() { return this.$tag === 5; }
    get is_In() { return this.$tag === 6; }
    get is_Nin() { return this.$tag === 7; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield Op.create_Eq();
      yield Op.create_Ne();
      yield Op.create_Lt();
      yield Op.create_Lte();
      yield Op.create_Gt();
      yield Op.create_Gte();
      yield Op.create_In();
      yield Op.create_Nin();
    }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Op.Eq";
      } else if (this.$tag === 1) {
        return "GoalIr.Op.Ne";
      } else if (this.$tag === 2) {
        return "GoalIr.Op.Lt";
      } else if (this.$tag === 3) {
        return "GoalIr.Op.Lte";
      } else if (this.$tag === 4) {
        return "GoalIr.Op.Gt";
      } else if (this.$tag === 5) {
        return "GoalIr.Op.Gte";
      } else if (this.$tag === 6) {
        return "GoalIr.Op.In";
      } else if (this.$tag === 7) {
        return "GoalIr.Op.Nin";
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
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Op.create_Eq();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Op.Default();
        }
      };
    }
  }

  $module.Cond = class Cond {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_CTrue() {
      let $dt = new Cond(0);
      return $dt;
    }
    static create_Cmp(op, l, r) {
      let $dt = new Cond(1);
      $dt.op = op;
      $dt.l = l;
      $dt.r = r;
      return $dt;
    }
    static create_And(a, b) {
      let $dt = new Cond(2);
      $dt.a = a;
      $dt.b = b;
      return $dt;
    }
    static create_Or(a, b) {
      let $dt = new Cond(3);
      $dt.a = a;
      $dt.b = b;
      return $dt;
    }
    static create_Not(c) {
      let $dt = new Cond(4);
      $dt.c = c;
      return $dt;
    }
    get is_CTrue() { return this.$tag === 0; }
    get is_Cmp() { return this.$tag === 1; }
    get is_And() { return this.$tag === 2; }
    get is_Or() { return this.$tag === 3; }
    get is_Not() { return this.$tag === 4; }
    get dtor_op() { return this.op; }
    get dtor_l() { return this.l; }
    get dtor_r() { return this.r; }
    get dtor_a() { return this.a; }
    get dtor_b() { return this.b; }
    get dtor_c() { return this.c; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Cond.CTrue";
      } else if (this.$tag === 1) {
        return "GoalIr.Cond.Cmp" + "(" + _dafny.toString(this.op) + ", " + _dafny.toString(this.l) + ", " + _dafny.toString(this.r) + ")";
      } else if (this.$tag === 2) {
        return "GoalIr.Cond.And" + "(" + _dafny.toString(this.a) + ", " + _dafny.toString(this.b) + ")";
      } else if (this.$tag === 3) {
        return "GoalIr.Cond.Or" + "(" + _dafny.toString(this.a) + ", " + _dafny.toString(this.b) + ")";
      } else if (this.$tag === 4) {
        return "GoalIr.Cond.Not" + "(" + _dafny.toString(this.c) + ")";
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
        return other.$tag === 1 && _dafny.areEqual(this.op, other.op) && _dafny.areEqual(this.l, other.l) && _dafny.areEqual(this.r, other.r);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.a, other.a) && _dafny.areEqual(this.b, other.b);
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.a, other.a) && _dafny.areEqual(this.b, other.b);
      } else if (this.$tag === 4) {
        return other.$tag === 4 && _dafny.areEqual(this.c, other.c);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Cond.create_CTrue();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Cond.Default();
        }
      };
    }
  }

  $module.ResPart = class ResPart {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_PartExact(id) {
      let $dt = new ResPart(0);
      $dt.id = id;
      return $dt;
    }
    static create_PartOneOf(ids) {
      let $dt = new ResPart(1);
      $dt.ids = ids;
      return $dt;
    }
    static create_PartRelated(rel, anchor) {
      let $dt = new ResPart(2);
      $dt.rel = rel;
      $dt.anchor = anchor;
      return $dt;
    }
    get is_PartExact() { return this.$tag === 0; }
    get is_PartOneOf() { return this.$tag === 1; }
    get is_PartRelated() { return this.$tag === 2; }
    get dtor_id() { return this.id; }
    get dtor_ids() { return this.ids; }
    get dtor_rel() { return this.rel; }
    get dtor_anchor() { return this.anchor; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.ResPart.PartExact" + "(" + this.id.toVerbatimString(true) + ")";
      } else if (this.$tag === 1) {
        return "GoalIr.ResPart.PartOneOf" + "(" + _dafny.toString(this.ids) + ")";
      } else if (this.$tag === 2) {
        return "GoalIr.ResPart.PartRelated" + "(" + this.rel.toVerbatimString(true) + ", " + this.anchor.toVerbatimString(true) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.id, other.id);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.ids, other.ids);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.rel, other.rel) && _dafny.areEqual(this.anchor, other.anchor);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.ResPart.create_PartExact(_dafny.Seq.UnicodeFromString(""));
    }
    static Rtd() {
      return class {
        static get Default() {
          return ResPart.Default();
        }
      };
    }
  }

  $module.ResSel = class ResSel {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Exact(id) {
      let $dt = new ResSel(0);
      $dt.id = id;
      return $dt;
    }
    static create_OneOf(ids) {
      let $dt = new ResSel(1);
      $dt.ids = ids;
      return $dt;
    }
    static create_Related(rel, anchor) {
      let $dt = new ResSel(2);
      $dt.rel = rel;
      $dt.anchor = anchor;
      return $dt;
    }
    static create_AnyRes(reason) {
      let $dt = new ResSel(3);
      $dt.reason = reason;
      return $dt;
    }
    static create_AllOf(parts) {
      let $dt = new ResSel(4);
      $dt.parts = parts;
      return $dt;
    }
    get is_Exact() { return this.$tag === 0; }
    get is_OneOf() { return this.$tag === 1; }
    get is_Related() { return this.$tag === 2; }
    get is_AnyRes() { return this.$tag === 3; }
    get is_AllOf() { return this.$tag === 4; }
    get dtor_id() { return this.id; }
    get dtor_ids() { return this.ids; }
    get dtor_rel() { return this.rel; }
    get dtor_anchor() { return this.anchor; }
    get dtor_reason() { return this.reason; }
    get dtor_parts() { return this.parts; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.ResSel.Exact" + "(" + this.id.toVerbatimString(true) + ")";
      } else if (this.$tag === 1) {
        return "GoalIr.ResSel.OneOf" + "(" + _dafny.toString(this.ids) + ")";
      } else if (this.$tag === 2) {
        return "GoalIr.ResSel.Related" + "(" + this.rel.toVerbatimString(true) + ", " + this.anchor.toVerbatimString(true) + ")";
      } else if (this.$tag === 3) {
        return "GoalIr.ResSel.AnyRes" + "(" + this.reason.toVerbatimString(true) + ")";
      } else if (this.$tag === 4) {
        return "GoalIr.ResSel.AllOf" + "(" + _dafny.toString(this.parts) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.id, other.id);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.ids, other.ids);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.rel, other.rel) && _dafny.areEqual(this.anchor, other.anchor);
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.reason, other.reason);
      } else if (this.$tag === 4) {
        return other.$tag === 4 && _dafny.areEqual(this.parts, other.parts);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.ResSel.create_Exact(_dafny.Seq.UnicodeFromString(""));
    }
    static Rtd() {
      return class {
        static get Default() {
          return ResSel.Default();
        }
      };
    }
  }

  $module.Grant = class Grant {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Grant(gid, verb, res, cond) {
      let $dt = new Grant(0);
      $dt.gid = gid;
      $dt.verb = verb;
      $dt.res = res;
      $dt.cond = cond;
      return $dt;
    }
    get is_Grant() { return this.$tag === 0; }
    get dtor_gid() { return this.gid; }
    get dtor_verb() { return this.verb; }
    get dtor_res() { return this.res; }
    get dtor_cond() { return this.cond; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Grant.Grant" + "(" + this.gid.toVerbatimString(true) + ", " + this.verb.toVerbatimString(true) + ", " + _dafny.toString(this.res) + ", " + _dafny.toString(this.cond) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.gid, other.gid) && _dafny.areEqual(this.verb, other.verb) && _dafny.areEqual(this.res, other.res) && _dafny.areEqual(this.cond, other.cond);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Grant.create_Grant(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), GoalIr.ResSel.Default(), GoalIr.Cond.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Grant.Default();
        }
      };
    }
  }

  $module.ProhTarget = class ProhTarget {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_PVerb(verb) {
      let $dt = new ProhTarget(0);
      $dt.verb = verb;
      return $dt;
    }
    static create_PEffect(cls) {
      let $dt = new ProhTarget(1);
      $dt.cls = cls;
      return $dt;
    }
    get is_PVerb() { return this.$tag === 0; }
    get is_PEffect() { return this.$tag === 1; }
    get dtor_verb() { return this.verb; }
    get dtor_cls() { return this.cls; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.ProhTarget.PVerb" + "(" + this.verb.toVerbatimString(true) + ")";
      } else if (this.$tag === 1) {
        return "GoalIr.ProhTarget.PEffect" + "(" + this.cls.toVerbatimString(true) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.verb, other.verb);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.cls, other.cls);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.ProhTarget.create_PVerb(_dafny.Seq.UnicodeFromString(""));
    }
    static Rtd() {
      return class {
        static get Default() {
          return ProhTarget.Default();
        }
      };
    }
  }

  $module.Prohibit = class Prohibit {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Prohibit(pid, target, res, cond) {
      let $dt = new Prohibit(0);
      $dt.pid = pid;
      $dt.target = target;
      $dt.res = res;
      $dt.cond = cond;
      return $dt;
    }
    get is_Prohibit() { return this.$tag === 0; }
    get dtor_pid() { return this.pid; }
    get dtor_target() { return this.target; }
    get dtor_res() { return this.res; }
    get dtor_cond() { return this.cond; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Prohibit.Prohibit" + "(" + this.pid.toVerbatimString(true) + ", " + _dafny.toString(this.target) + ", " + _dafny.toString(this.res) + ", " + _dafny.toString(this.cond) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.pid, other.pid) && _dafny.areEqual(this.target, other.target) && _dafny.areEqual(this.res, other.res) && _dafny.areEqual(this.cond, other.cond);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Prohibit.create_Prohibit(_dafny.Seq.UnicodeFromString(""), GoalIr.ProhTarget.Default(), GoalIr.ResSel.Default(), GoalIr.Cond.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Prohibit.Default();
        }
      };
    }
  }

  $module.Agg = class Agg {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_ACount() {
      let $dt = new Agg(0);
      return $dt;
    }
    static create_ASum() {
      let $dt = new Agg(1);
      return $dt;
    }
    static create_AMax() {
      let $dt = new Agg(2);
      return $dt;
    }
    static create_ADistinct() {
      let $dt = new Agg(3);
      return $dt;
    }
    get is_ACount() { return this.$tag === 0; }
    get is_ASum() { return this.$tag === 1; }
    get is_AMax() { return this.$tag === 2; }
    get is_ADistinct() { return this.$tag === 3; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield Agg.create_ACount();
      yield Agg.create_ASum();
      yield Agg.create_AMax();
      yield Agg.create_ADistinct();
    }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Agg.ACount";
      } else if (this.$tag === 1) {
        return "GoalIr.Agg.ASum";
      } else if (this.$tag === 2) {
        return "GoalIr.Agg.AMax";
      } else if (this.$tag === 3) {
        return "GoalIr.Agg.ADistinct";
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
      return GoalIr.Agg.create_ACount();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Agg.Default();
        }
      };
    }
  }

  $module.Sel = class Sel {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_SelGids(gids) {
      let $dt = new Sel(0);
      $dt.gids = gids;
      return $dt;
    }
    static create_SelEffect(cls) {
      let $dt = new Sel(1);
      $dt.cls = cls;
      return $dt;
    }
    get is_SelGids() { return this.$tag === 0; }
    get is_SelEffect() { return this.$tag === 1; }
    get dtor_gids() { return this.gids; }
    get dtor_cls() { return this.cls; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Sel.SelGids" + "(" + _dafny.toString(this.gids) + ")";
      } else if (this.$tag === 1) {
        return "GoalIr.Sel.SelEffect" + "(" + this.cls.toVerbatimString(true) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.gids, other.gids);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.cls, other.cls);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Sel.create_SelGids(_dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Sel.Default();
        }
      };
    }
  }

  $module.Window = class Window {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_WTask() {
      let $dt = new Window(0);
      return $dt;
    }
    static create_WSliding(ms) {
      let $dt = new Window(1);
      $dt.ms = ms;
      return $dt;
    }
    static create_WPeriod(ms, t0) {
      let $dt = new Window(2);
      $dt.ms = ms;
      $dt.t0 = t0;
      return $dt;
    }
    static create_WLifetime() {
      let $dt = new Window(3);
      return $dt;
    }
    get is_WTask() { return this.$tag === 0; }
    get is_WSliding() { return this.$tag === 1; }
    get is_WPeriod() { return this.$tag === 2; }
    get is_WLifetime() { return this.$tag === 3; }
    get dtor_ms() { return this.ms; }
    get dtor_t0() { return this.t0; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Window.WTask";
      } else if (this.$tag === 1) {
        return "GoalIr.Window.WSliding" + "(" + _dafny.toString(this.ms) + ")";
      } else if (this.$tag === 2) {
        return "GoalIr.Window.WPeriod" + "(" + _dafny.toString(this.ms) + ", " + _dafny.toString(this.t0) + ")";
      } else if (this.$tag === 3) {
        return "GoalIr.Window.WLifetime";
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
        return other.$tag === 1 && _dafny.areEqual(this.ms, other.ms);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.ms, other.ms) && _dafny.areEqual(this.t0, other.t0);
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Window.create_WTask();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Window.Default();
        }
      };
    }
  }

  $module.Scope = class Scope {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_SSession() {
      let $dt = new Scope(0);
      return $dt;
    }
    static create_SPrincipal() {
      let $dt = new Scope(1);
      return $dt;
    }
    static create_SOrg() {
      let $dt = new Scope(2);
      return $dt;
    }
    static create_SFleet(agents) {
      let $dt = new Scope(3);
      $dt.agents = agents;
      return $dt;
    }
    get is_SSession() { return this.$tag === 0; }
    get is_SPrincipal() { return this.$tag === 1; }
    get is_SOrg() { return this.$tag === 2; }
    get is_SFleet() { return this.$tag === 3; }
    get dtor_agents() { return this.agents; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Scope.SSession";
      } else if (this.$tag === 1) {
        return "GoalIr.Scope.SPrincipal";
      } else if (this.$tag === 2) {
        return "GoalIr.Scope.SOrg";
      } else if (this.$tag === 3) {
        return "GoalIr.Scope.SFleet" + "(" + _dafny.toString(this.agents) + ")";
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
        return other.$tag === 3 && _dafny.areEqual(this.agents, other.agents);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Scope.create_SSession();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Scope.Default();
        }
      };
    }
  }

  $module.OnExceed = class OnExceed {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_OnDeny() {
      let $dt = new OnExceed(0);
      return $dt;
    }
    static create_OnEscalate() {
      let $dt = new OnExceed(1);
      return $dt;
    }
    get is_OnDeny() { return this.$tag === 0; }
    get is_OnEscalate() { return this.$tag === 1; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield OnExceed.create_OnDeny();
      yield OnExceed.create_OnEscalate();
    }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.OnExceed.OnDeny";
      } else if (this.$tag === 1) {
        return "GoalIr.OnExceed.OnEscalate";
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
      return GoalIr.OnExceed.create_OnDeny();
    }
    static Rtd() {
      return class {
        static get Default() {
          return OnExceed.Default();
        }
      };
    }
  }

  $module.BCore = class BCore {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_BCore(agg, value, key, window, scope, cap, onExceed) {
      let $dt = new BCore(0);
      $dt.agg = agg;
      $dt.value = value;
      $dt.key = key;
      $dt.window = window;
      $dt.scope = scope;
      $dt.cap = cap;
      $dt.onExceed = onExceed;
      return $dt;
    }
    get is_BCore() { return this.$tag === 0; }
    get dtor_agg() { return this.agg; }
    get dtor_value() { return this.value; }
    get dtor_key() { return this.key; }
    get dtor_window() { return this.window; }
    get dtor_scope() { return this.scope; }
    get dtor_cap() { return this.cap; }
    get dtor_onExceed() { return this.onExceed; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.BCore.BCore" + "(" + _dafny.toString(this.agg) + ", " + _dafny.toString(this.value) + ", " + this.key.toVerbatimString(true) + ", " + _dafny.toString(this.window) + ", " + _dafny.toString(this.scope) + ", " + _dafny.toString(this.cap) + ", " + _dafny.toString(this.onExceed) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.agg, other.agg) && _dafny.areEqual(this.value, other.value) && _dafny.areEqual(this.key, other.key) && _dafny.areEqual(this.window, other.window) && _dafny.areEqual(this.scope, other.scope) && _dafny.areEqual(this.cap, other.cap) && _dafny.areEqual(this.onExceed, other.onExceed);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.BCore.create_BCore(GoalIr.Agg.Default(), GoalIr.Term.Default(), _dafny.Seq.UnicodeFromString(""), GoalIr.Window.Default(), GoalIr.Scope.Default(), GoalIr.Q.Default(), GoalIr.OnExceed.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return BCore.Default();
        }
      };
    }
  }

  $module.Bound = class Bound {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Bound(bid, sel, core) {
      let $dt = new Bound(0);
      $dt.bid = bid;
      $dt.sel = sel;
      $dt.core = core;
      return $dt;
    }
    get is_Bound() { return this.$tag === 0; }
    get dtor_bid() { return this.bid; }
    get dtor_sel() { return this.sel; }
    get dtor_core() { return this.core; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Bound.Bound" + "(" + this.bid.toVerbatimString(true) + ", " + _dafny.toString(this.sel) + ", " + _dafny.toString(this.core) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.bid, other.bid) && _dafny.areEqual(this.sel, other.sel) && _dafny.areEqual(this.core, other.core);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Bound.create_Bound(_dafny.Seq.UnicodeFromString(""), GoalIr.Sel.Default(), GoalIr.BCore.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Bound.Default();
        }
      };
    }
  }

  $module.Validity = class Validity {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Validity(notBefore, notAfter, maxIdle) {
      let $dt = new Validity(0);
      $dt.notBefore = notBefore;
      $dt.notAfter = notAfter;
      $dt.maxIdle = maxIdle;
      return $dt;
    }
    get is_Validity() { return this.$tag === 0; }
    get dtor_notBefore() { return this.notBefore; }
    get dtor_notAfter() { return this.notAfter; }
    get dtor_maxIdle() { return this.maxIdle; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Validity.Validity" + "(" + _dafny.toString(this.notBefore) + ", " + _dafny.toString(this.notAfter) + ", " + _dafny.toString(this.maxIdle) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.notBefore, other.notBefore) && _dafny.areEqual(this.notAfter, other.notAfter) && _dafny.areEqual(this.maxIdle, other.maxIdle);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Validity.create_Validity(_dafny.ZERO, _dafny.ZERO, _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Validity.Default();
        }
      };
    }
  }

  $module.Delegation = class Delegation {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Delegation(maxDepth, narrowOnly, mayTouch) {
      let $dt = new Delegation(0);
      $dt.maxDepth = maxDepth;
      $dt.narrowOnly = narrowOnly;
      $dt.mayTouch = mayTouch;
      return $dt;
    }
    get is_Delegation() { return this.$tag === 0; }
    get dtor_maxDepth() { return this.maxDepth; }
    get dtor_narrowOnly() { return this.narrowOnly; }
    get dtor_mayTouch() { return this.mayTouch; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Delegation.Delegation" + "(" + _dafny.toString(this.maxDepth) + ", " + _dafny.toString(this.narrowOnly) + ", " + _dafny.toString(this.mayTouch) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.maxDepth, other.maxDepth) && this.narrowOnly === other.narrowOnly && _dafny.areEqual(this.mayTouch, other.mayTouch);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Delegation.create_Delegation(_dafny.ZERO, false, _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Delegation.Default();
        }
      };
    }
  }

  $module.Hole = class Hole {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Hole(hid, q, domain, affects, global) {
      let $dt = new Hole(0);
      $dt.hid = hid;
      $dt.q = q;
      $dt.domain = domain;
      $dt.affects = affects;
      $dt.global = global;
      return $dt;
    }
    get is_Hole() { return this.$tag === 0; }
    get dtor_hid() { return this.hid; }
    get dtor_q() { return this.q; }
    get dtor_domain() { return this.domain; }
    get dtor_affects() { return this.affects; }
    get dtor_global() { return this.global; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Hole.Hole" + "(" + this.hid.toVerbatimString(true) + ", " + this.q.toVerbatimString(true) + ", " + _dafny.toString(this.domain) + ", " + _dafny.toString(this.affects) + ", " + _dafny.toString(this.global) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.hid, other.hid) && _dafny.areEqual(this.q, other.q) && _dafny.areEqual(this.domain, other.domain) && _dafny.areEqual(this.affects, other.affects) && this.global === other.global;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Hole.create_Hole(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.of(), _dafny.Seq.of(), false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Hole.Default();
        }
      };
    }
  }

  $module.Goal = class Goal {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Goal(v, principal, ontDigest, nlDigest, sources, grants, prohibits, bounds, validity, deleg, escalateOn, wildcardAck, holes) {
      let $dt = new Goal(0);
      $dt.v = v;
      $dt.principal = principal;
      $dt.ontDigest = ontDigest;
      $dt.nlDigest = nlDigest;
      $dt.sources = sources;
      $dt.grants = grants;
      $dt.prohibits = prohibits;
      $dt.bounds = bounds;
      $dt.validity = validity;
      $dt.deleg = deleg;
      $dt.escalateOn = escalateOn;
      $dt.wildcardAck = wildcardAck;
      $dt.holes = holes;
      return $dt;
    }
    get is_Goal() { return this.$tag === 0; }
    get dtor_v() { return this.v; }
    get dtor_principal() { return this.principal; }
    get dtor_ontDigest() { return this.ontDigest; }
    get dtor_nlDigest() { return this.nlDigest; }
    get dtor_sources() { return this.sources; }
    get dtor_grants() { return this.grants; }
    get dtor_prohibits() { return this.prohibits; }
    get dtor_bounds() { return this.bounds; }
    get dtor_validity() { return this.validity; }
    get dtor_deleg() { return this.deleg; }
    get dtor_escalateOn() { return this.escalateOn; }
    get dtor_wildcardAck() { return this.wildcardAck; }
    get dtor_holes() { return this.holes; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Goal.Goal" + "(" + _dafny.toString(this.v) + ", " + this.principal.toVerbatimString(true) + ", " + this.ontDigest.toVerbatimString(true) + ", " + this.nlDigest.toVerbatimString(true) + ", " + _dafny.toString(this.sources) + ", " + _dafny.toString(this.grants) + ", " + _dafny.toString(this.prohibits) + ", " + _dafny.toString(this.bounds) + ", " + _dafny.toString(this.validity) + ", " + _dafny.toString(this.deleg) + ", " + _dafny.toString(this.escalateOn) + ", " + _dafny.toString(this.wildcardAck) + ", " + _dafny.toString(this.holes) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.v, other.v) && _dafny.areEqual(this.principal, other.principal) && _dafny.areEqual(this.ontDigest, other.ontDigest) && _dafny.areEqual(this.nlDigest, other.nlDigest) && _dafny.areEqual(this.sources, other.sources) && _dafny.areEqual(this.grants, other.grants) && _dafny.areEqual(this.prohibits, other.prohibits) && _dafny.areEqual(this.bounds, other.bounds) && _dafny.areEqual(this.validity, other.validity) && _dafny.areEqual(this.deleg, other.deleg) && _dafny.areEqual(this.escalateOn, other.escalateOn) && _dafny.areEqual(this.wildcardAck, other.wildcardAck) && _dafny.areEqual(this.holes, other.holes);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Goal.create_Goal(_dafny.ZERO, _dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.of(), _dafny.Seq.of(), _dafny.Seq.of(), _dafny.Seq.of(), GoalIr.Validity.Default(), GoalIr.Delegation.Default(), _dafny.Seq.of(), _dafny.Seq.of(), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Goal.Default();
        }
      };
    }
  }

  $module.ParamDecl = class ParamDecl {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_ParamDecl(path, ty) {
      let $dt = new ParamDecl(0);
      $dt.path = path;
      $dt.ty = ty;
      return $dt;
    }
    get is_ParamDecl() { return this.$tag === 0; }
    get dtor_path() { return this.path; }
    get dtor_ty() { return this.ty; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.ParamDecl.ParamDecl" + "(" + this.path.toVerbatimString(true) + ", " + _dafny.toString(this.ty) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.path, other.path) && _dafny.areEqual(this.ty, other.ty);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.ParamDecl.create_ParamDecl(_dafny.Seq.UnicodeFromString(""), GoalIr.Ty.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return ParamDecl.Default();
        }
      };
    }
  }

  $module.VerbDecl = class VerbDecl {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_VerbDecl(verb, cls, params) {
      let $dt = new VerbDecl(0);
      $dt.verb = verb;
      $dt.cls = cls;
      $dt.params = params;
      return $dt;
    }
    get is_VerbDecl() { return this.$tag === 0; }
    get dtor_verb() { return this.verb; }
    get dtor_cls() { return this.cls; }
    get dtor_params() { return this.params; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.VerbDecl.VerbDecl" + "(" + this.verb.toVerbatimString(true) + ", " + this.cls.toVerbatimString(true) + ", " + _dafny.toString(this.params) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.verb, other.verb) && _dafny.areEqual(this.cls, other.cls) && _dafny.areEqual(this.params, other.params);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.VerbDecl.create_VerbDecl(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return VerbDecl.Default();
        }
      };
    }
  }

  $module.RelDecl = class RelDecl {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_RelDecl(rel, anchor, members) {
      let $dt = new RelDecl(0);
      $dt.rel = rel;
      $dt.anchor = anchor;
      $dt.members = members;
      return $dt;
    }
    get is_RelDecl() { return this.$tag === 0; }
    get dtor_rel() { return this.rel; }
    get dtor_anchor() { return this.anchor; }
    get dtor_members() { return this.members; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.RelDecl.RelDecl" + "(" + this.rel.toVerbatimString(true) + ", " + this.anchor.toVerbatimString(true) + ", " + _dafny.toString(this.members) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.rel, other.rel) && _dafny.areEqual(this.anchor, other.anchor) && _dafny.areEqual(this.members, other.members);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.RelDecl.create_RelDecl(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return RelDecl.Default();
        }
      };
    }
  }

  $module.Ontology = class Ontology {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Ontology(verbs, rels) {
      let $dt = new Ontology(0);
      $dt.verbs = verbs;
      $dt.rels = rels;
      return $dt;
    }
    get is_Ontology() { return this.$tag === 0; }
    get dtor_verbs() { return this.verbs; }
    get dtor_rels() { return this.rels; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Ontology.Ontology" + "(" + _dafny.toString(this.verbs) + ", " + _dafny.toString(this.rels) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.verbs, other.verbs) && _dafny.areEqual(this.rels, other.rels);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Ontology.create_Ontology(_dafny.Seq.of(), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Ontology.Default();
        }
      };
    }
  }

  $module.Act = class Act {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Act(verb, res, params, t, sess, prin, org, agent, depth) {
      let $dt = new Act(0);
      $dt.verb = verb;
      $dt.res = res;
      $dt.params = params;
      $dt.t = t;
      $dt.sess = sess;
      $dt.prin = prin;
      $dt.org = org;
      $dt.agent = agent;
      $dt.depth = depth;
      return $dt;
    }
    get is_Act() { return this.$tag === 0; }
    get dtor_verb() { return this.verb; }
    get dtor_res() { return this.res; }
    get dtor_params() { return this.params; }
    get dtor_t() { return this.t; }
    get dtor_sess() { return this.sess; }
    get dtor_prin() { return this.prin; }
    get dtor_org() { return this.org; }
    get dtor_agent() { return this.agent; }
    get dtor_depth() { return this.depth; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Act.Act" + "(" + this.verb.toVerbatimString(true) + ", " + this.res.toVerbatimString(true) + ", " + _dafny.toString(this.params) + ", " + _dafny.toString(this.t) + ", " + this.sess.toVerbatimString(true) + ", " + this.prin.toVerbatimString(true) + ", " + this.org.toVerbatimString(true) + ", " + this.agent.toVerbatimString(true) + ", " + _dafny.toString(this.depth) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.verb, other.verb) && _dafny.areEqual(this.res, other.res) && _dafny.areEqual(this.params, other.params) && _dafny.areEqual(this.t, other.t) && _dafny.areEqual(this.sess, other.sess) && _dafny.areEqual(this.prin, other.prin) && _dafny.areEqual(this.org, other.org) && _dafny.areEqual(this.agent, other.agent) && _dafny.areEqual(this.depth, other.depth);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Act.create_Act(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Map.Empty, _dafny.ZERO, _dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Act.Default();
        }
      };
    }
  }

  $module.Adm = class Adm {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Adm(gid, act) {
      let $dt = new Adm(0);
      $dt.gid = gid;
      $dt.act = act;
      return $dt;
    }
    get is_Adm() { return this.$tag === 0; }
    get dtor_gid() { return this.gid; }
    get dtor_act() { return this.act; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Adm.Adm" + "(" + this.gid.toVerbatimString(true) + ", " + _dafny.toString(this.act) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.gid, other.gid) && _dafny.areEqual(this.act, other.act);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Adm.create_Adm(_dafny.Seq.UnicodeFromString(""), GoalIr.Act.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Adm.Default();
        }
      };
    }
  }

  $module.Hist = class Hist {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Hist(adms, last, aggs) {
      let $dt = new Hist(0);
      $dt.adms = adms;
      $dt.last = last;
      $dt.aggs = aggs;
      return $dt;
    }
    get is_Hist() { return this.$tag === 0; }
    get dtor_adms() { return this.adms; }
    get dtor_last() { return this.last; }
    get dtor_aggs() { return this.aggs; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.Hist.Hist" + "(" + _dafny.toString(this.adms) + ", " + _dafny.toString(this.last) + ", " + _dafny.toString(this.aggs) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.adms, other.adms) && _dafny.areEqual(this.last, other.last) && _dafny.areEqual(this.aggs, other.aggs);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.Hist.create_Hist(_dafny.Seq.of(), _dafny.ZERO, _dafny.Map.Empty);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Hist.Default();
        }
      };
    }
  }

  $module.ResPat = class ResPat {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_PStar() {
      let $dt = new ResPat(0);
      return $dt;
    }
    static create_PSet(ids) {
      let $dt = new ResPat(1);
      $dt.ids = ids;
      return $dt;
    }
    get is_PStar() { return this.$tag === 0; }
    get is_PSet() { return this.$tag === 1; }
    get dtor_ids() { return this.ids; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.ResPat.PStar";
      } else if (this.$tag === 1) {
        return "GoalIr.ResPat.PSet" + "(" + _dafny.toString(this.ids) + ")";
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
        return other.$tag === 1 && _dafny.areEqual(this.ids, other.ids);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.ResPat.create_PStar();
    }
    static Rtd() {
      return class {
        static get Default() {
          return ResPat.Default();
        }
      };
    }
  }

  $module.LSel = class LSel {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_LSel(gids, verbs) {
      let $dt = new LSel(0);
      $dt.gids = gids;
      $dt.verbs = verbs;
      return $dt;
    }
    get is_LSel() { return this.$tag === 0; }
    get dtor_gids() { return this.gids; }
    get dtor_verbs() { return this.verbs; }
    toString() {
      if (this.$tag === 0) {
        return "GoalIr.LSel.LSel" + "(" + _dafny.toString(this.gids) + ", " + _dafny.toString(this.verbs) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.gids, other.gids) && _dafny.areEqual(this.verbs, other.verbs);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalIr.LSel.create_LSel(_dafny.Seq.of(), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return LSel.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module GoalIr
let GoalCompile = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "GoalCompile._default";
    }
    _parentTraits() {
      return [];
    }
    static EvalN(c, a, h) {
      let _source0 = c;
      {
        if (_source0.is_NTrue) {
          return GoalIr.__default.KT;
        }
      }
      {
        if (_source0.is_NFalse) {
          return GoalIr.__default.KF;
        }
      }
      {
        if (_source0.is_NAtom) {
          let _0_op = (_source0).op;
          let _1_l = (_source0).l;
          let _2_r = (_source0).r;
          return GoalIr.__default.CmpT(_0_op, GoalIr.__default.EvalT(_1_l, a, h), GoalIr.__default.EvalT(_2_r, a, h));
        }
      }
      {
        if (_source0.is_NAnd) {
          let _3_x = (_source0).a;
          let _4_y = (_source0).b;
          return GoalIr.__default.AndK(GoalCompile.__default.EvalN(_3_x, a, h), GoalCompile.__default.EvalN(_4_y, a, h));
        }
      }
      {
        let _5_x = (_source0).a;
        let _6_y = (_source0).b;
        return GoalIr.__default.OrK(GoalCompile.__default.EvalN(_5_x, a, h), GoalCompile.__default.EvalN(_6_y, a, h));
      }
    };
    static Nnf(c, pos) {
      let _source0 = c;
      {
        if (_source0.is_CTrue) {
          if (pos) {
            return GoalCompile.NC.create_NTrue();
          } else {
            return GoalCompile.NC.create_NFalse();
          }
        }
      }
      {
        if (_source0.is_Cmp) {
          let _0_op = (_source0).op;
          let _1_l = (_source0).l;
          let _2_r = (_source0).r;
          return GoalCompile.NC.create_NAtom(((pos) ? (_0_op) : (GoalIr.__default.NegOp(_0_op))), _1_l, _2_r);
        }
      }
      {
        if (_source0.is_And) {
          let _3_x = (_source0).a;
          let _4_y = (_source0).b;
          if (pos) {
            return GoalCompile.NC.create_NAnd(GoalCompile.__default.Nnf(_3_x, true), GoalCompile.__default.Nnf(_4_y, true));
          } else {
            return GoalCompile.NC.create_NOr(GoalCompile.__default.Nnf(_3_x, false), GoalCompile.__default.Nnf(_4_y, false));
          }
        }
      }
      {
        if (_source0.is_Or) {
          let _5_x = (_source0).a;
          let _6_y = (_source0).b;
          if (pos) {
            return GoalCompile.NC.create_NOr(GoalCompile.__default.Nnf(_5_x, true), GoalCompile.__default.Nnf(_6_y, true));
          } else {
            return GoalCompile.NC.create_NAnd(GoalCompile.__default.Nnf(_5_x, false), GoalCompile.__default.Nnf(_6_y, false));
          }
        }
      }
      {
        let _7_x = (_source0).c;
        return GoalCompile.__default.Nnf(_7_x, !(pos));
      }
    };
    static ProhOneP(p, a, h) {
      let _0_m = GoalIr.__default.AndK(GoalIr.__default.B2T(_dafny.Seq.contains((p).dtor_verbs, (a).dtor_verb)), GoalIr.__default.AndK(GoalIr.__default.B2T(GoalIr.__default.ResOk((p).dtor_res, (a).dtor_res)), GoalCompile.__default.EvalN((p).dtor_cond, a, h)));
      if ((_0_m).isEqualTo(GoalIr.__default.KT)) {
        return GoalIr.__default.Deny;
      } else if ((_0_m).isEqualTo(GoalIr.__default.KU)) {
        return GoalIr.__default.Escalate;
      } else {
        return GoalIr.__default.Allow;
      }
    };
    static ProhDecP(ps, a, h) {
      if ((new BigNumber((ps).length)).isEqualTo(_dafny.ZERO)) {
        return GoalIr.__default.Allow;
      } else {
        return GoalIr.__default.MeetD(GoalCompile.__default.ProhOneP((ps)[_dafny.ZERO], a, h), GoalCompile.__default.ProhDecP((ps).slice(_dafny.ONE), a, h));
      }
    };
    static EscDecP(cs, a, h) {
      if ((new BigNumber((cs).length)).isEqualTo(_dafny.ZERO)) {
        return GoalIr.__default.Allow;
      } else {
        return GoalIr.__default.MeetD(GoalIr.__default.EscOne(GoalCompile.__default.EvalN((cs)[_dafny.ZERO], a, h)), GoalCompile.__default.EscDecP((cs).slice(_dafny.ONE), a, h));
      }
    };
    static CeilOne(c, gid, a, h) {
      if (GoalIr.__default.AppliesL((c).dtor_sel, gid, (a).dtor_verb)) {
        return GoalIr.__default.BoundStat((c).dtor_core, (c).dtor_sel, a, h);
      } else {
        return GoalIr.__default.Allow;
      }
    };
    static CeilsDecP(cs, gid, a, h) {
      if ((new BigNumber((cs).length)).isEqualTo(_dafny.ZERO)) {
        return GoalIr.__default.Allow;
      } else {
        return GoalIr.__default.MeetD(GoalCompile.__default.CeilOne((cs)[_dafny.ZERO], gid, a, h), GoalCompile.__default.CeilsDecP((cs).slice(_dafny.ONE), gid, a, h));
      }
    };
    static PredMatch(p, dg, a, h) {
      return GoalIr.__default.AndK(GoalIr.__default.B2T((_dafny.areEqual((a).dtor_verb, (p).dtor_verb)) && (GoalIr.__default.DelegOk(dg, (p).dtor_gid, a))), GoalIr.__default.AndK(GoalIr.__default.B2T(GoalIr.__default.ResOk((p).dtor_res, (a).dtor_res)), GoalCompile.__default.EvalN((p).dtor_cond, a, h)));
    };
    static PredDec(p, ceils, dg, a, h) {
      return GoalIr.__default.MeetD(GoalIr.__default.DecOfTri(GoalCompile.__default.PredMatch(p, dg, a, h)), GoalCompile.__default.CeilsDecP(ceils, (p).dtor_gid, a, h));
    };
    static PredsDecP(ps, ceils, dg, a, h) {
      if ((new BigNumber((ps).length)).isEqualTo(_dafny.ZERO)) {
        return GoalIr.__default.Deny;
      } else {
        return GoalIr.__default.JoinD(GoalCompile.__default.PredDec((ps)[_dafny.ZERO], ceils, dg, a, h), GoalCompile.__default.PredsDecP((ps).slice(_dafny.ONE), ceils, dg, a, h));
      }
    };
    static DP(p, a, h) {
      return GoalIr.__default.MeetD(GoalIr.__default.ValidityDec((p).dtor_validity, (p).dtor_deleg, a, h), GoalIr.__default.MeetD(GoalCompile.__default.ProhDecP((p).dtor_prohs, a, h), GoalIr.__default.MeetD(GoalCompile.__default.EscDecP((p).dtor_escs, a, h), GoalCompile.__default.PredsDecP((p).dtor_preds, (p).dtor_ceils, (p).dtor_deleg, a, h))));
    };
    static LowerGrants(ont, gs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((gs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(GoalCompile.LPred.create_LPred(((gs)[_dafny.ZERO]).dtor_gid, ((gs)[_dafny.ZERO]).dtor_verb, GoalIr.__default.ResolveSel(ont, ((gs)[_dafny.ZERO]).dtor_res), GoalCompile.__default.Nnf(((gs)[_dafny.ZERO]).dtor_cond, true))));
          let _in0 = ont;
          let _in1 = (gs).slice(_dafny.ONE);
          ont = _in0;
          gs = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static LowerProhs(ont, ps) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((ps).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(GoalCompile.LProh.create_LProh(((ps)[_dafny.ZERO]).dtor_pid, GoalIr.__default.ProhVerbs(ont, ((ps)[_dafny.ZERO]).dtor_target), GoalIr.__default.ResolveSel(ont, ((ps)[_dafny.ZERO]).dtor_res), GoalCompile.__default.Nnf(((ps)[_dafny.ZERO]).dtor_cond, true))));
          let _in0 = ont;
          let _in1 = (ps).slice(_dafny.ONE);
          ont = _in0;
          ps = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static LowerBounds(ont, bs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((bs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(GoalCompile.LCeil.create_LCeil(((bs)[_dafny.ZERO]).dtor_bid, GoalIr.__default.ResolveBSel(ont, ((bs)[_dafny.ZERO]).dtor_sel), ((bs)[_dafny.ZERO]).dtor_core)));
          let _in0 = ont;
          let _in1 = (bs).slice(_dafny.ONE);
          ont = _in0;
          bs = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static LowerEscs(cs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((cs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(GoalCompile.__default.Nnf((cs)[_dafny.ZERO], true)));
          let _in0 = (cs).slice(_dafny.ONE);
          cs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static Lower(ont, g) {
      return GoalCompile.Pol.create_Pol(GoalCompile.__default.LowerGrants(ont, (g).dtor_grants), GoalCompile.__default.LowerProhs(ont, (g).dtor_prohibits), GoalCompile.__default.LowerBounds(ont, (g).dtor_bounds), GoalCompile.__default.LowerEscs((g).dtor_escalateOn), (g).dtor_validity, (g).dtor_deleg);
    };
    static DependsOn(hs, gid) {
      return ((_dafny.ZERO).isLessThan(new BigNumber((hs).length))) && (((((hs)[_dafny.ZERO]).dtor_global) || (_dafny.Seq.contains(((hs)[_dafny.ZERO]).dtor_affects, gid))) || (GoalCompile.__default.DependsOn((hs).slice(_dafny.ONE), gid)));
    };
    static StripGrants(hs, gs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((gs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, ((GoalCompile.__default.DependsOn(hs, ((gs)[_dafny.ZERO]).dtor_gid)) ? (_dafny.Seq.of()) : (_dafny.Seq.of((gs)[_dafny.ZERO]))));
          let _in0 = hs;
          let _in1 = (gs).slice(_dafny.ONE);
          hs = _in0;
          gs = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static Strip(g) {
      let _0_dt__update__tmp_h0 = g;
      let _1_dt__update_hholes_h0 = _dafny.Seq.of();
      let _2_dt__update_hgrants_h0 = GoalCompile.__default.StripGrants((g).dtor_holes, (g).dtor_grants);
      return GoalIr.Goal.create_Goal((_0_dt__update__tmp_h0).dtor_v, (_0_dt__update__tmp_h0).dtor_principal, (_0_dt__update__tmp_h0).dtor_ontDigest, (_0_dt__update__tmp_h0).dtor_nlDigest, (_0_dt__update__tmp_h0).dtor_sources, _2_dt__update_hgrants_h0, (_0_dt__update__tmp_h0).dtor_prohibits, (_0_dt__update__tmp_h0).dtor_bounds, (_0_dt__update__tmp_h0).dtor_validity, (_0_dt__update__tmp_h0).dtor_deleg, (_0_dt__update__tmp_h0).dtor_escalateOn, (_0_dt__update__tmp_h0).dtor_wildcardAck, _1_dt__update_hholes_h0);
    };
    static BadGrants(ont, g, gs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((gs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, ((GoalIr.__default.GrantOk(ont, g, (gs)[_dafny.ZERO])) ? (_dafny.Seq.of()) : (_dafny.Seq.of(((gs)[_dafny.ZERO]).dtor_gid))));
          let _in0 = ont;
          let _in1 = g;
          let _in2 = (gs).slice(_dafny.ONE);
          ont = _in0;
          g = _in1;
          gs = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static BadProhibits(ont, ps) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((ps).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, ((GoalIr.__default.ProhibitOk(ont, (ps)[_dafny.ZERO])) ? (_dafny.Seq.of()) : (_dafny.Seq.of(((ps)[_dafny.ZERO]).dtor_pid))));
          let _in0 = ont;
          let _in1 = (ps).slice(_dafny.ONE);
          ont = _in0;
          ps = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static BadBounds(ont, g, bs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((bs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, ((GoalIr.__default.BoundOk(ont, g, (bs)[_dafny.ZERO])) ? (_dafny.Seq.of()) : (_dafny.Seq.of(((bs)[_dafny.ZERO]).dtor_bid))));
          let _in0 = ont;
          let _in1 = g;
          let _in2 = (bs).slice(_dafny.ONE);
          ont = _in0;
          g = _in1;
          bs = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static BadHoles(g, hs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((hs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, ((GoalIr.__default.HoleOk(g, (hs)[_dafny.ZERO])) ? (_dafny.Seq.of()) : (_dafny.Seq.of(((hs)[_dafny.ZERO]).dtor_hid))));
          let _in0 = g;
          let _in1 = (hs).slice(_dafny.ONE);
          g = _in0;
          hs = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static TypeReasons(ont, g) {
      return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.Concat(((GoalIr.__default.Sorted4(g)) ? (_dafny.Seq.of()) : (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("not_canonical_order")))), (((new BigNumber((GoalCompile.__default.BadGrants(ont, g, (g).dtor_grants)).length)).isEqualTo(_dafny.ZERO)) ? (_dafny.Seq.of()) : (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("ill_typed_grant"))))), (((new BigNumber((GoalCompile.__default.BadProhibits(ont, (g).dtor_prohibits)).length)).isEqualTo(_dafny.ZERO)) ? (_dafny.Seq.of()) : (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("ill_typed_prohibit"))))), (((new BigNumber((GoalCompile.__default.BadBounds(ont, g, (g).dtor_bounds)).length)).isEqualTo(_dafny.ZERO)) ? (_dafny.Seq.of()) : (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("ill_typed_bound"))))), ((GoalIr.__default.EscsTyped(ont, g)) ? (_dafny.Seq.of()) : (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("ill_typed_escalation"))))), ((GoalIr.__default.ValidityOk((g).dtor_validity, (g).dtor_deleg, g)) ? (_dafny.Seq.of()) : (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("bad_validity_or_delegation"))))), (((new BigNumber((GoalCompile.__default.BadHoles(g, (g).dtor_holes)).length)).isEqualTo(_dafny.ZERO)) ? (_dafny.Seq.of()) : (_dafny.Seq.of(_dafny.Seq.UnicodeFromString("bad_hole")))));
    };
    static Compile(ont, g) {
      let _0_rs = GoalCompile.__default.TypeReasons(ont, g);
      if ((_dafny.ZERO).isLessThan(new BigNumber((_0_rs).length))) {
        return GoalCompile.CResult.create_CEscalate(_0_rs);
      } else {
        return GoalCompile.CResult.create_Compiled(GoalCompile.__default.Lower(ont, GoalCompile.__default.Strip(g)));
      }
    };
    static ResNarrows(p2, p1) {
      return ((p1).is_PStar) || ((((p2).is_PSet) && ((p1).is_PSet)) && (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((p2).dtor_ids).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber(((p2).dtor_ids).length)))) || (_dafny.Seq.contains((p1).dtor_ids, ((p2).dtor_ids)[_0_i]));
      })));
    };
    static CondNarrows(c2, c1) {
      return (_dafny.areEqual(c2, c1)) || (((c2).is_And) && ((_dafny.areEqual((c2).dtor_a, c1)) || (_dafny.areEqual((c2).dtor_b, c1))));
    };
    static GrantNarrows(ont, g2, g1) {
      return (((_dafny.areEqual((g2).dtor_gid, (g1).dtor_gid)) && (_dafny.areEqual((g2).dtor_verb, (g1).dtor_verb))) && (GoalCompile.__default.ResNarrows(GoalIr.__default.ResolveSel(ont, (g2).dtor_res), GoalIr.__default.ResolveSel(ont, (g1).dtor_res)))) && (GoalCompile.__default.CondNarrows((g2).dtor_cond, (g1).dtor_cond));
    };
    static SubsetOf(xs, ys) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((xs).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((xs).length)))) || (_dafny.Seq.contains(ys, (xs)[_0_i]));
      });
    };
    static Refines(ont, g2, g1) {
      return ((((((((_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((g2).dtor_grants).length)), true, function (_forall_var_0) {
        let _0_i = _forall_var_0;
        return !(((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber(((g2).dtor_grants).length)))) || (_dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber(((g1).dtor_grants).length)), false, function (_exists_var_0) {
          let _1_j = _exists_var_0;
          return (((_dafny.ZERO).isLessThanOrEqualTo(_1_j)) && ((_1_j).isLessThan(new BigNumber(((g1).dtor_grants).length)))) && (GoalCompile.__default.GrantNarrows(ont, ((g2).dtor_grants)[_0_i], ((g1).dtor_grants)[_1_j]));
        }));
      })) && (GoalCompile.__default.SubsetOf((g1).dtor_prohibits, (g2).dtor_prohibits))) && (GoalCompile.__default.SubsetOf((g1).dtor_bounds, (g2).dtor_bounds))) && (GoalCompile.__default.SubsetOf((g1).dtor_escalateOn, (g2).dtor_escalateOn))) && ((((g1).dtor_validity).dtor_notBefore).isLessThanOrEqualTo(((g2).dtor_validity).dtor_notBefore))) && ((((g2).dtor_validity).dtor_notAfter).isLessThanOrEqualTo(((g1).dtor_validity).dtor_notAfter))) && (((((g1).dtor_validity).dtor_maxIdle).isLessThanOrEqualTo(_dafny.ZERO)) || (((_dafny.ZERO).isLessThan(((g2).dtor_validity).dtor_maxIdle)) && ((((g2).dtor_validity).dtor_maxIdle).isLessThanOrEqualTo(((g1).dtor_validity).dtor_maxIdle))))) && ((((g2).dtor_deleg).dtor_maxDepth).isLessThanOrEqualTo(((g1).dtor_deleg).dtor_maxDepth))) && (GoalCompile.__default.SubsetOf(((g2).dtor_deleg).dtor_mayTouch, ((g1).dtor_deleg).dtor_mayTouch));
    };
    static BoundOne(ont, b, gid, a, h) {
      let _0_s = GoalIr.__default.ResolveBSel(ont, (b).dtor_sel);
      if (GoalIr.__default.AppliesL(_0_s, gid, (a).dtor_verb)) {
        return GoalIr.__default.BoundStat((b).dtor_core, _0_s, a, h);
      } else {
        return GoalIr.__default.Allow;
      }
    };
    static Refines2V(g2, g1) {
      return ((((((g1).dtor_validity).dtor_notBefore).isLessThanOrEqualTo(((g2).dtor_validity).dtor_notBefore)) && ((((g2).dtor_validity).dtor_notAfter).isLessThanOrEqualTo(((g1).dtor_validity).dtor_notAfter))) && (((((g1).dtor_validity).dtor_maxIdle).isLessThanOrEqualTo(_dafny.ZERO)) || (((_dafny.ZERO).isLessThan(((g2).dtor_validity).dtor_maxIdle)) && ((((g2).dtor_validity).dtor_maxIdle).isLessThanOrEqualTo(((g1).dtor_validity).dtor_maxIdle))))) && ((((g2).dtor_deleg).dtor_maxDepth).isLessThanOrEqualTo(((g1).dtor_deleg).dtor_maxDepth));
    };
  };

  $module.NC = class NC {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_NTrue() {
      let $dt = new NC(0);
      return $dt;
    }
    static create_NFalse() {
      let $dt = new NC(1);
      return $dt;
    }
    static create_NAtom(op, l, r) {
      let $dt = new NC(2);
      $dt.op = op;
      $dt.l = l;
      $dt.r = r;
      return $dt;
    }
    static create_NAnd(a, b) {
      let $dt = new NC(3);
      $dt.a = a;
      $dt.b = b;
      return $dt;
    }
    static create_NOr(a, b) {
      let $dt = new NC(4);
      $dt.a = a;
      $dt.b = b;
      return $dt;
    }
    get is_NTrue() { return this.$tag === 0; }
    get is_NFalse() { return this.$tag === 1; }
    get is_NAtom() { return this.$tag === 2; }
    get is_NAnd() { return this.$tag === 3; }
    get is_NOr() { return this.$tag === 4; }
    get dtor_op() { return this.op; }
    get dtor_l() { return this.l; }
    get dtor_r() { return this.r; }
    get dtor_a() { return this.a; }
    get dtor_b() { return this.b; }
    toString() {
      if (this.$tag === 0) {
        return "GoalCompile.NC.NTrue";
      } else if (this.$tag === 1) {
        return "GoalCompile.NC.NFalse";
      } else if (this.$tag === 2) {
        return "GoalCompile.NC.NAtom" + "(" + _dafny.toString(this.op) + ", " + _dafny.toString(this.l) + ", " + _dafny.toString(this.r) + ")";
      } else if (this.$tag === 3) {
        return "GoalCompile.NC.NAnd" + "(" + _dafny.toString(this.a) + ", " + _dafny.toString(this.b) + ")";
      } else if (this.$tag === 4) {
        return "GoalCompile.NC.NOr" + "(" + _dafny.toString(this.a) + ", " + _dafny.toString(this.b) + ")";
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
        return other.$tag === 2 && _dafny.areEqual(this.op, other.op) && _dafny.areEqual(this.l, other.l) && _dafny.areEqual(this.r, other.r);
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.a, other.a) && _dafny.areEqual(this.b, other.b);
      } else if (this.$tag === 4) {
        return other.$tag === 4 && _dafny.areEqual(this.a, other.a) && _dafny.areEqual(this.b, other.b);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalCompile.NC.create_NTrue();
    }
    static Rtd() {
      return class {
        static get Default() {
          return NC.Default();
        }
      };
    }
  }

  $module.LPred = class LPred {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_LPred(gid, verb, res, cond) {
      let $dt = new LPred(0);
      $dt.gid = gid;
      $dt.verb = verb;
      $dt.res = res;
      $dt.cond = cond;
      return $dt;
    }
    get is_LPred() { return this.$tag === 0; }
    get dtor_gid() { return this.gid; }
    get dtor_verb() { return this.verb; }
    get dtor_res() { return this.res; }
    get dtor_cond() { return this.cond; }
    toString() {
      if (this.$tag === 0) {
        return "GoalCompile.LPred.LPred" + "(" + this.gid.toVerbatimString(true) + ", " + this.verb.toVerbatimString(true) + ", " + _dafny.toString(this.res) + ", " + _dafny.toString(this.cond) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.gid, other.gid) && _dafny.areEqual(this.verb, other.verb) && _dafny.areEqual(this.res, other.res) && _dafny.areEqual(this.cond, other.cond);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalCompile.LPred.create_LPred(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), GoalIr.ResPat.Default(), GoalCompile.NC.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return LPred.Default();
        }
      };
    }
  }

  $module.LProh = class LProh {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_LProh(pid, verbs, res, cond) {
      let $dt = new LProh(0);
      $dt.pid = pid;
      $dt.verbs = verbs;
      $dt.res = res;
      $dt.cond = cond;
      return $dt;
    }
    get is_LProh() { return this.$tag === 0; }
    get dtor_pid() { return this.pid; }
    get dtor_verbs() { return this.verbs; }
    get dtor_res() { return this.res; }
    get dtor_cond() { return this.cond; }
    toString() {
      if (this.$tag === 0) {
        return "GoalCompile.LProh.LProh" + "(" + this.pid.toVerbatimString(true) + ", " + _dafny.toString(this.verbs) + ", " + _dafny.toString(this.res) + ", " + _dafny.toString(this.cond) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.pid, other.pid) && _dafny.areEqual(this.verbs, other.verbs) && _dafny.areEqual(this.res, other.res) && _dafny.areEqual(this.cond, other.cond);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalCompile.LProh.create_LProh(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.of(), GoalIr.ResPat.Default(), GoalCompile.NC.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return LProh.Default();
        }
      };
    }
  }

  $module.LCeil = class LCeil {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_LCeil(bid, sel, core) {
      let $dt = new LCeil(0);
      $dt.bid = bid;
      $dt.sel = sel;
      $dt.core = core;
      return $dt;
    }
    get is_LCeil() { return this.$tag === 0; }
    get dtor_bid() { return this.bid; }
    get dtor_sel() { return this.sel; }
    get dtor_core() { return this.core; }
    toString() {
      if (this.$tag === 0) {
        return "GoalCompile.LCeil.LCeil" + "(" + this.bid.toVerbatimString(true) + ", " + _dafny.toString(this.sel) + ", " + _dafny.toString(this.core) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.bid, other.bid) && _dafny.areEqual(this.sel, other.sel) && _dafny.areEqual(this.core, other.core);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalCompile.LCeil.create_LCeil(_dafny.Seq.UnicodeFromString(""), GoalIr.LSel.Default(), GoalIr.BCore.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return LCeil.Default();
        }
      };
    }
  }

  $module.Pol = class Pol {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Pol(preds, prohs, ceils, escs, validity, deleg) {
      let $dt = new Pol(0);
      $dt.preds = preds;
      $dt.prohs = prohs;
      $dt.ceils = ceils;
      $dt.escs = escs;
      $dt.validity = validity;
      $dt.deleg = deleg;
      return $dt;
    }
    get is_Pol() { return this.$tag === 0; }
    get dtor_preds() { return this.preds; }
    get dtor_prohs() { return this.prohs; }
    get dtor_ceils() { return this.ceils; }
    get dtor_escs() { return this.escs; }
    get dtor_validity() { return this.validity; }
    get dtor_deleg() { return this.deleg; }
    toString() {
      if (this.$tag === 0) {
        return "GoalCompile.Pol.Pol" + "(" + _dafny.toString(this.preds) + ", " + _dafny.toString(this.prohs) + ", " + _dafny.toString(this.ceils) + ", " + _dafny.toString(this.escs) + ", " + _dafny.toString(this.validity) + ", " + _dafny.toString(this.deleg) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.preds, other.preds) && _dafny.areEqual(this.prohs, other.prohs) && _dafny.areEqual(this.ceils, other.ceils) && _dafny.areEqual(this.escs, other.escs) && _dafny.areEqual(this.validity, other.validity) && _dafny.areEqual(this.deleg, other.deleg);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalCompile.Pol.create_Pol(_dafny.Seq.of(), _dafny.Seq.of(), _dafny.Seq.of(), _dafny.Seq.of(), GoalIr.Validity.Default(), GoalIr.Delegation.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Pol.Default();
        }
      };
    }
  }

  $module.CResult = class CResult {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Compiled(p) {
      let $dt = new CResult(0);
      $dt.p = p;
      return $dt;
    }
    static create_CEscalate(reasons) {
      let $dt = new CResult(1);
      $dt.reasons = reasons;
      return $dt;
    }
    get is_Compiled() { return this.$tag === 0; }
    get is_CEscalate() { return this.$tag === 1; }
    get dtor_p() { return this.p; }
    get dtor_reasons() { return this.reasons; }
    toString() {
      if (this.$tag === 0) {
        return "GoalCompile.CResult.Compiled" + "(" + _dafny.toString(this.p) + ")";
      } else if (this.$tag === 1) {
        return "GoalCompile.CResult.CEscalate" + "(" + _dafny.toString(this.reasons) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.p, other.p);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.reasons, other.reasons);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalCompile.CResult.create_Compiled(GoalCompile.Pol.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return CResult.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module GoalCompile
let GoalWitness = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "GoalWitness._default";
    }
    _parentTraits() {
      return [];
    }
    static Applicable(cs, gid, verb) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((cs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, ((GoalIr.__default.AppliesL(((cs)[_dafny.ZERO]).dtor_sel, gid, verb)) ? (_dafny.Seq.of(((cs)[_dafny.ZERO]).dtor_bid)) : (_dafny.Seq.of())));
          let _in0 = (cs).slice(_dafny.ONE);
          let _in1 = gid;
          let _in2 = verb;
          cs = _in0;
          gid = _in1;
          verb = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static FindAllow(ps, ceils, dg, a, h) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((ps).length)).isEqualTo(_dafny.ZERO)) {
          return GoalIr.Option.create_None();
        } else if ((GoalCompile.__default.PredDec((ps)[_dafny.ZERO], ceils, dg, a, h)).isEqualTo(GoalIr.__default.Allow)) {
          return GoalIr.Option.create_Some((ps)[_dafny.ZERO]);
        } else {
          let _in0 = (ps).slice(_dafny.ONE);
          let _in1 = ceils;
          let _in2 = dg;
          let _in3 = a;
          let _in4 = h;
          ps = _in0;
          ceils = _in1;
          dg = _in2;
          a = _in3;
          h = _in4;
          continue TAIL_CALL_START;
        }
      }
    };
    static DecideW(p, a, h) {
      let _0_d = GoalCompile.__default.DP(p, a, h);
      if ((_0_d).isEqualTo(GoalIr.__default.Allow)) {
        let _source0 = GoalWitness.__default.FindAllow((p).dtor_preds, (p).dtor_ceils, (p).dtor_deleg, a, h);
        {
          if (_source0.is_Some) {
            let _1_pr = (_source0).v;
            return _dafny.Tuple.of(GoalIr.__default.Allow, GoalWitness.Wit.create_Wit((_1_pr).dtor_gid, GoalWitness.__default.Applicable((p).dtor_ceils, (_1_pr).dtor_gid, (a).dtor_verb)));
          }
        }
        {
          return _dafny.Tuple.of(GoalIr.__default.Deny, GoalWitness.Wit.create_Wit(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.of()));
        }
      } else {
        return _dafny.Tuple.of(_0_d, GoalWitness.Wit.create_Wit(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.of()));
      }
    };
    static AnyPredAllows(ps, gid, ceils, dg, a, h) {
      return ((_dafny.ZERO).isLessThan(new BigNumber((ps).length))) && (((_dafny.areEqual(((ps)[_dafny.ZERO]).dtor_gid, gid)) && ((GoalCompile.__default.PredDec((ps)[_dafny.ZERO], ceils, dg, a, h)).isEqualTo(GoalIr.__default.Allow))) || (GoalWitness.__default.AnyPredAllows((ps).slice(_dafny.ONE), gid, ceils, dg, a, h)));
    };
    static VerifyWitness(p, a, h, w) {
      return (((((GoalIr.__default.ValidityDec((p).dtor_validity, (p).dtor_deleg, a, h)).isEqualTo(GoalIr.__default.Allow)) && ((GoalCompile.__default.ProhDecP((p).dtor_prohs, a, h)).isEqualTo(GoalIr.__default.Allow))) && ((GoalCompile.__default.EscDecP((p).dtor_escs, a, h)).isEqualTo(GoalIr.__default.Allow))) && (GoalWitness.__default.AnyPredAllows((p).dtor_preds, (w).dtor_gid, (p).dtor_ceils, (p).dtor_deleg, a, h))) && (_dafny.areEqual((w).dtor_bids, GoalWitness.__default.Applicable((p).dtor_ceils, (w).dtor_gid, (a).dtor_verb)));
    };
    static PepAllows(d, ans, pd, ad, hh) {
      return ((d).isEqualTo(GoalIr.__default.Allow)) || (((((((d).isEqualTo(GoalIr.__default.Escalate)) && ((ans).is_Some)) && (((ans).dtor_v).dtor_sigOk)) && (_dafny.areEqual(((ans).dtor_v).dtor_policyDigest, pd))) && (_dafny.areEqual(((ans).dtor_v).dtor_actionDigest, ad))) && (_dafny.areEqual(((ans).dtor_v).dtor_histHead, hh)));
    };
  };

  $module.Wit = class Wit {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Wit(gid, bids) {
      let $dt = new Wit(0);
      $dt.gid = gid;
      $dt.bids = bids;
      return $dt;
    }
    get is_Wit() { return this.$tag === 0; }
    get dtor_gid() { return this.gid; }
    get dtor_bids() { return this.bids; }
    toString() {
      if (this.$tag === 0) {
        return "GoalWitness.Wit.Wit" + "(" + this.gid.toVerbatimString(true) + ", " + _dafny.toString(this.bids) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.gid, other.gid) && _dafny.areEqual(this.bids, other.bids);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalWitness.Wit.create_Wit(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return Wit.Default();
        }
      };
    }
  }

  $module.Answer = class Answer {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Answer(sigOk, policyDigest, actionDigest, histHead) {
      let $dt = new Answer(0);
      $dt.sigOk = sigOk;
      $dt.policyDigest = policyDigest;
      $dt.actionDigest = actionDigest;
      $dt.histHead = histHead;
      return $dt;
    }
    get is_Answer() { return this.$tag === 0; }
    get dtor_sigOk() { return this.sigOk; }
    get dtor_policyDigest() { return this.policyDigest; }
    get dtor_actionDigest() { return this.actionDigest; }
    get dtor_histHead() { return this.histHead; }
    toString() {
      if (this.$tag === 0) {
        return "GoalWitness.Answer.Answer" + "(" + _dafny.toString(this.sigOk) + ", " + this.policyDigest.toVerbatimString(true) + ", " + this.actionDigest.toVerbatimString(true) + ", " + this.histHead.toVerbatimString(true) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.sigOk === other.sigOk && _dafny.areEqual(this.policyDigest, other.policyDigest) && _dafny.areEqual(this.actionDigest, other.actionDigest) && _dafny.areEqual(this.histHead, other.histHead);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalWitness.Answer.create_Answer(false, _dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""));
    }
    static Rtd() {
      return class {
        static get Default() {
          return Answer.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module GoalWitness
let GoalRender = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "GoalRender._default";
    }
    _parentTraits() {
      return [];
    }
    static EncStr(s) {
      return _dafny.Seq.of(GoalRender.Tok.create_TS(s));
    };
    static DecStr(ts) {
      if (((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TS)) {
        return GoalRender.PR.create_Ok(((ts)[_dafny.ZERO]).dtor_s, (ts).slice(_dafny.ONE));
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncInt(i) {
      return _dafny.Seq.of(GoalRender.Tok.create_TI(i));
    };
    static DecInt(ts) {
      if (((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) {
        return GoalRender.PR.create_Ok(((ts)[_dafny.ZERO]).dtor_i, (ts).slice(_dafny.ONE));
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncBool(b) {
      return _dafny.Seq.of(GoalRender.Tok.create_TI(((b) ? (_dafny.ONE) : (_dafny.ZERO))));
    };
    static DecBool(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && (((((ts)[_dafny.ZERO]).dtor_i).isEqualTo(_dafny.ZERO)) || ((((ts)[_dafny.ZERO]).dtor_i).isEqualTo(_dafny.ONE)))) {
        return GoalRender.PR.create_Ok((((ts)[_dafny.ZERO]).dtor_i).isEqualTo(_dafny.ONE), (ts).slice(_dafny.ONE));
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncUnit(u) {
      let _source0 = u;
      {
        if (_source0.is_UMoney) {
          let _0_c = (_source0).ccy;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(300))), GoalRender.__default.EncStr(_0_c));
        }
      }
      {
        if (_source0.is_UCount) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(301)));
        }
      }
      {
        if (_source0.is_UDuration) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(302)));
        }
      }
      {
        if (_source0.is_UInstant) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(303)));
        }
      }
      {
        if (_source0.is_UBytes) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(304)));
        }
      }
      {
        return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(305)));
      }
    };
    static DecUnit(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(300))) {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Ok) {
            let _0_c = (_source0).v;
            let _1_r = (_source0).rest;
            return GoalRender.PR.create_Ok(GoalIr.Unit.create_UMoney(_0_c), _1_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(301))) {
        return GoalRender.PR.create_Ok(GoalIr.Unit.create_UCount(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(302))) {
        return GoalRender.PR.create_Ok(GoalIr.Unit.create_UDuration(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(303))) {
        return GoalRender.PR.create_Ok(GoalIr.Unit.create_UInstant(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(304))) {
        return GoalRender.PR.create_Ok(GoalIr.Unit.create_UBytes(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(305))) {
        return GoalRender.PR.create_Ok(GoalIr.Unit.create_URatio(), (ts).slice(_dafny.ONE));
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncQ(q) {
      return _dafny.Seq.Concat(GoalRender.__default.EncUnit((q).dtor_u), GoalRender.__default.EncInt((q).dtor_n));
    };
    static DecQ(ts) {
      let _source0 = GoalRender.__default.DecUnit(ts);
      {
        if (_source0.is_Fail) {
          return GoalRender.PR.create_Fail();
        }
      }
      {
        let _0_u = (_source0).v;
        let _1_r = (_source0).rest;
        let _source1 = GoalRender.__default.DecInt(_1_r);
        {
          if (_source1.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _2_n = (_source1).v;
          let _3_r2 = (_source1).rest;
          return GoalRender.PR.create_Ok(GoalIr.Q.create_Q(_0_u, _2_n), _3_r2);
        }
      }
    };
    static EncTy(t) {
      let _source0 = t;
      {
        if (_source0.is_TyQ) {
          let _0_u = (_source0).u;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(310))), GoalRender.__default.EncUnit(_0_u));
        }
      }
      {
        return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(311)));
      }
    };
    static DecTy(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(310))) {
        let _source0 = GoalRender.__default.DecUnit((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Ok) {
            let _0_u = (_source0).v;
            let _1_r = (_source0).rest;
            return GoalRender.PR.create_Ok(GoalIr.Ty.create_TyQ(_0_u), _1_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(311))) {
        return GoalRender.PR.create_Ok(GoalIr.Ty.create_TyS(), (ts).slice(_dafny.ONE));
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncAtom(a) {
      let _source0 = a;
      {
        if (_source0.is_AQ) {
          let _0_q = (_source0).q;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(320))), GoalRender.__default.EncQ(_0_q));
        }
      }
      {
        let _1_s = (_source0).s;
        return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(321))), GoalRender.__default.EncStr(_1_s));
      }
    };
    static DecAtom(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(320))) {
        let _source0 = GoalRender.__default.DecQ((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Ok) {
            let _0_q = (_source0).v;
            let _1_r = (_source0).rest;
            return GoalRender.PR.create_Ok(GoalIr.Atom.create_AQ(_0_q), _1_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(321))) {
        let _source1 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source1.is_Ok) {
            let _2_s = (_source1).v;
            let _3_r = (_source1).rest;
            return GoalRender.PR.create_Ok(GoalIr.Atom.create_AS(_2_s), _3_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncAtomsElems(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, GoalRender.__default.EncAtom((xs)[_dafny.ZERO]));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static EncAtoms(xs) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber((xs).length))), GoalRender.__default.EncAtomsElems(xs));
    };
    static DecAtomsElems(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Seq.of(), ts);
      } else {
        let _source0 = GoalRender.__default.DecAtom(ts);
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_x = (_source0).v;
          let _1_r = (_source0).rest;
          let _source1 = GoalRender.__default.DecAtomsElems(_1_r, (n).minus(_dafny.ONE));
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_xs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(_dafny.Seq.Concat(_dafny.Seq.of(_0_x), _2_xs), _3_r2);
          }
        }
      }
    };
    static DecAtoms(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalRender.__default.DecAtomsElems((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncV(v) {
      let _source0 = v;
      {
        if (_source0.is_VQ) {
          let _0_q = (_source0).q;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(330))), GoalRender.__default.EncQ(_0_q));
        }
      }
      {
        if (_source0.is_VS) {
          let _1_s = (_source0).s;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(331))), GoalRender.__default.EncStr(_1_s));
        }
      }
      {
        let _2_items = (_source0).items;
        return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(332))), GoalRender.__default.EncAtoms(_2_items));
      }
    };
    static DecV(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(330))) {
        let _source0 = GoalRender.__default.DecQ((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Ok) {
            let _0_q = (_source0).v;
            let _1_r = (_source0).rest;
            return GoalRender.PR.create_Ok(GoalIr.V.create_VQ(_0_q), _1_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(331))) {
        let _source1 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source1.is_Ok) {
            let _2_s = (_source1).v;
            let _3_r = (_source1).rest;
            return GoalRender.PR.create_Ok(GoalIr.V.create_VS(_2_s), _3_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(332))) {
        let _source2 = GoalRender.__default.DecAtoms((ts).slice(_dafny.ONE));
        {
          if (_source2.is_Ok) {
            let _4_xs = (_source2).v;
            let _5_r = (_source2).rest;
            return GoalRender.PR.create_Ok(GoalIr.V.create_VSet(_4_xs), _5_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncTerm(t) {
      let _source0 = t;
      {
        if (_source0.is_Param) {
          let _0_p = (_source0).path;
          let _1_ty = (_source0).ty;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(340))), _dafny.Seq.Concat(GoalRender.__default.EncStr(_0_p), GoalRender.__default.EncTy(_1_ty)));
        }
      }
      {
        if (_source0.is_Lit) {
          let _2_v = (_source0).v;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(341))), GoalRender.__default.EncV(_2_v));
        }
      }
      {
        let _3_b = (_source0).bid;
        let _4_u = (_source0).u;
        return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(342))), _dafny.Seq.Concat(GoalRender.__default.EncStr(_3_b), GoalRender.__default.EncUnit(_4_u)));
      }
    };
    static DecTerm(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(340))) {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_p = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecTy(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_ty = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(GoalIr.Term.create_Param(_0_p, _2_ty), _3_r2);
          }
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(341))) {
        let _source2 = GoalRender.__default.DecV((ts).slice(_dafny.ONE));
        {
          if (_source2.is_Ok) {
            let _4_v = (_source2).v;
            let _5_r = (_source2).rest;
            return GoalRender.PR.create_Ok(GoalIr.Term.create_Lit(_4_v), _5_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(342))) {
        let _source3 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source3.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _6_b = (_source3).v;
          let _7_r1 = (_source3).rest;
          let _source4 = GoalRender.__default.DecUnit(_7_r1);
          {
            if (_source4.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _8_u = (_source4).v;
            let _9_r2 = (_source4).rest;
            return GoalRender.PR.create_Ok(GoalIr.Term.create_HistAgg(_6_b, _8_u), _9_r2);
          }
        }
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static OpIdx(op) {
      let _source0 = op;
      {
        if (_source0.is_Eq) {
          return _dafny.ZERO;
        }
      }
      {
        if (_source0.is_Ne) {
          return _dafny.ONE;
        }
      }
      {
        if (_source0.is_Lt) {
          return new BigNumber(2);
        }
      }
      {
        if (_source0.is_Lte) {
          return new BigNumber(3);
        }
      }
      {
        if (_source0.is_Gt) {
          return new BigNumber(4);
        }
      }
      {
        if (_source0.is_Gte) {
          return new BigNumber(5);
        }
      }
      {
        if (_source0.is_In) {
          return new BigNumber(6);
        }
      }
      {
        return new BigNumber(7);
      }
    };
    static EncOp(op) {
      return _dafny.Seq.of(GoalRender.Tok.create_TKw((new BigNumber(350)).plus(GoalRender.__default.OpIdx(op))));
    };
    static DecOp(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(350))) {
        return GoalRender.PR.create_Ok(GoalIr.Op.create_Eq(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(351))) {
        return GoalRender.PR.create_Ok(GoalIr.Op.create_Ne(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(352))) {
        return GoalRender.PR.create_Ok(GoalIr.Op.create_Lt(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(353))) {
        return GoalRender.PR.create_Ok(GoalIr.Op.create_Lte(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(354))) {
        return GoalRender.PR.create_Ok(GoalIr.Op.create_Gt(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(355))) {
        return GoalRender.PR.create_Ok(GoalIr.Op.create_Gte(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(356))) {
        return GoalRender.PR.create_Ok(GoalIr.Op.create_In(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(357))) {
        return GoalRender.PR.create_Ok(GoalIr.Op.create_Nin(), (ts).slice(_dafny.ONE));
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncCond(c) {
      let _source0 = c;
      {
        if (_source0.is_CTrue) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(360)));
        }
      }
      {
        if (_source0.is_Cmp) {
          let _0_op = (_source0).op;
          let _1_l = (_source0).l;
          let _2_r = (_source0).r;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(361))), _dafny.Seq.Concat(GoalRender.__default.EncOp(_0_op), _dafny.Seq.Concat(GoalRender.__default.EncTerm(_1_l), GoalRender.__default.EncTerm(_2_r))));
        }
      }
      {
        if (_source0.is_And) {
          let _3_x = (_source0).a;
          let _4_y = (_source0).b;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(362))), _dafny.Seq.Concat(GoalRender.__default.EncCond(_3_x), GoalRender.__default.EncCond(_4_y)));
        }
      }
      {
        if (_source0.is_Or) {
          let _5_x = (_source0).a;
          let _6_y = (_source0).b;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(363))), _dafny.Seq.Concat(GoalRender.__default.EncCond(_5_x), GoalRender.__default.EncCond(_6_y)));
        }
      }
      {
        let _7_x = (_source0).c;
        return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(364))), GoalRender.__default.EncCond(_7_x));
      }
    };
    static DecCond(ts, fuel) {
      if ((((fuel).isEqualTo(_dafny.ZERO)) || ((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO))) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(360))) {
        return GoalRender.PR.create_Ok(GoalIr.Cond.create_CTrue(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(361))) {
        let _source0 = GoalRender.__default.DecOp((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_op = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecTerm(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_l = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalRender.__default.DecTerm(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_r = (_source2).v;
              let _5_r3 = (_source2).rest;
              return GoalRender.PR.create_Ok(GoalIr.Cond.create_Cmp(_0_op, _2_l, _4_r), _5_r3);
            }
          }
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(362))) {
        let _source3 = GoalRender.__default.DecCond((ts).slice(_dafny.ONE), (fuel).minus(_dafny.ONE));
        {
          if (_source3.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _6_x = (_source3).v;
          let _7_r1 = (_source3).rest;
          let _source4 = GoalRender.__default.DecCond(_7_r1, (fuel).minus(_dafny.ONE));
          {
            if (_source4.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _8_y = (_source4).v;
            let _9_r2 = (_source4).rest;
            return GoalRender.PR.create_Ok(GoalIr.Cond.create_And(_6_x, _8_y), _9_r2);
          }
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(363))) {
        let _source5 = GoalRender.__default.DecCond((ts).slice(_dafny.ONE), (fuel).minus(_dafny.ONE));
        {
          if (_source5.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _10_x = (_source5).v;
          let _11_r1 = (_source5).rest;
          let _source6 = GoalRender.__default.DecCond(_11_r1, (fuel).minus(_dafny.ONE));
          {
            if (_source6.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _12_y = (_source6).v;
            let _13_r2 = (_source6).rest;
            return GoalRender.PR.create_Ok(GoalIr.Cond.create_Or(_10_x, _12_y), _13_r2);
          }
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(364))) {
        let _source7 = GoalRender.__default.DecCond((ts).slice(_dafny.ONE), (fuel).minus(_dafny.ONE));
        {
          if (_source7.is_Ok) {
            let _14_x = (_source7).v;
            let _15_r = (_source7).rest;
            return GoalRender.PR.create_Ok(GoalIr.Cond.create_Not(_14_x), _15_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static DecCondTop(ts) {
      return GoalRender.__default.DecCond(ts, new BigNumber((ts).length));
    };
    static Depth(c) {
      let _source0 = c;
      {
        if (_source0.is_CTrue) {
          return _dafny.ONE;
        }
      }
      {
        if (_source0.is_Cmp) {
          return _dafny.ONE;
        }
      }
      {
        if (_source0.is_And) {
          let _0_x = (_source0).a;
          let _1_y = (_source0).b;
          return (_dafny.ONE).plus((((GoalRender.__default.Depth(_1_y)).isLessThanOrEqualTo(GoalRender.__default.Depth(_0_x))) ? (GoalRender.__default.Depth(_0_x)) : (GoalRender.__default.Depth(_1_y))));
        }
      }
      {
        if (_source0.is_Or) {
          let _2_x = (_source0).a;
          let _3_y = (_source0).b;
          return (_dafny.ONE).plus((((GoalRender.__default.Depth(_3_y)).isLessThanOrEqualTo(GoalRender.__default.Depth(_2_x))) ? (GoalRender.__default.Depth(_2_x)) : (GoalRender.__default.Depth(_3_y))));
        }
      }
      {
        let _4_x = (_source0).c;
        return (_dafny.ONE).plus(GoalRender.__default.Depth(_4_x));
      }
    };
    static EncPart(p) {
      let _source0 = p;
      {
        if (_source0.is_PartExact) {
          let _0_id = (_source0).id;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(375))), GoalRender.__default.EncStr(_0_id));
        }
      }
      {
        if (_source0.is_PartOneOf) {
          let _1_ids = (_source0).ids;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(376))), GoalRender.__default.EncStrs(_1_ids));
        }
      }
      {
        let _2_rel = (_source0).rel;
        let _3_anchor = (_source0).anchor;
        return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(377))), _dafny.Seq.Concat(GoalRender.__default.EncStr(_2_rel), GoalRender.__default.EncStr(_3_anchor)));
      }
    };
    static DecPart(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(375))) {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Ok) {
            let _0_id = (_source0).v;
            let _1_r = (_source0).rest;
            return GoalRender.PR.create_Ok(GoalIr.ResPart.create_PartExact(_0_id), _1_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(376))) {
        let _source1 = GoalRender.__default.DecStrs((ts).slice(_dafny.ONE));
        {
          if (_source1.is_Ok) {
            let _2_ids = (_source1).v;
            let _3_r = (_source1).rest;
            return GoalRender.PR.create_Ok(GoalIr.ResPart.create_PartOneOf(_2_ids), _3_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(377))) {
        let _source2 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source2.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _4_rel = (_source2).v;
          let _5_r1 = (_source2).rest;
          let _source3 = GoalRender.__default.DecStr(_5_r1);
          {
            if (_source3.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _6_anchor = (_source3).v;
            let _7_r2 = (_source3).rest;
            return GoalRender.PR.create_Ok(GoalIr.ResPart.create_PartRelated(_4_rel, _6_anchor), _7_r2);
          }
        }
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncPartsElems(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, GoalRender.__default.EncPart((xs)[_dafny.ZERO]));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static EncParts(xs) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber((xs).length))), GoalRender.__default.EncPartsElems(xs));
    };
    static DecPartsElems(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Seq.of(), ts);
      } else {
        let _source0 = GoalRender.__default.DecPart(ts);
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_x = (_source0).v;
          let _1_r = (_source0).rest;
          let _source1 = GoalRender.__default.DecPartsElems(_1_r, (n).minus(_dafny.ONE));
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_xs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(_dafny.Seq.Concat(_dafny.Seq.of(_0_x), _2_xs), _3_r2);
          }
        }
      }
    };
    static DecParts(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalRender.__default.DecPartsElems((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncResSel(s) {
      let _source0 = s;
      {
        if (_source0.is_Exact) {
          let _0_id = (_source0).id;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(370))), GoalRender.__default.EncStr(_0_id));
        }
      }
      {
        if (_source0.is_OneOf) {
          let _1_ids = (_source0).ids;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(371))), GoalRender.__default.EncStrs(_1_ids));
        }
      }
      {
        if (_source0.is_Related) {
          let _2_rel = (_source0).rel;
          let _3_anchor = (_source0).anchor;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(372))), _dafny.Seq.Concat(GoalRender.__default.EncStr(_2_rel), GoalRender.__default.EncStr(_3_anchor)));
        }
      }
      {
        if (_source0.is_AnyRes) {
          let _4_reason = (_source0).reason;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(373))), GoalRender.__default.EncStr(_4_reason));
        }
      }
      {
        let _5_ps = (_source0).parts;
        return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(374))), GoalRender.__default.EncParts(_5_ps));
      }
    };
    static DecResSel(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(370))) {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Ok) {
            let _0_id = (_source0).v;
            let _1_r = (_source0).rest;
            return GoalRender.PR.create_Ok(GoalIr.ResSel.create_Exact(_0_id), _1_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(371))) {
        let _source1 = GoalRender.__default.DecStrs((ts).slice(_dafny.ONE));
        {
          if (_source1.is_Ok) {
            let _2_ids = (_source1).v;
            let _3_r = (_source1).rest;
            return GoalRender.PR.create_Ok(GoalIr.ResSel.create_OneOf(_2_ids), _3_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(372))) {
        let _source2 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source2.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _4_rel = (_source2).v;
          let _5_r1 = (_source2).rest;
          let _source3 = GoalRender.__default.DecStr(_5_r1);
          {
            if (_source3.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _6_anchor = (_source3).v;
            let _7_r2 = (_source3).rest;
            return GoalRender.PR.create_Ok(GoalIr.ResSel.create_Related(_4_rel, _6_anchor), _7_r2);
          }
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(373))) {
        let _source4 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source4.is_Ok) {
            let _8_reason = (_source4).v;
            let _9_r = (_source4).rest;
            return GoalRender.PR.create_Ok(GoalIr.ResSel.create_AnyRes(_8_reason), _9_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(374))) {
        let _source5 = GoalRender.__default.DecParts((ts).slice(_dafny.ONE));
        {
          if (_source5.is_Ok) {
            let _10_ps = (_source5).v;
            let _11_r = (_source5).rest;
            return GoalRender.PR.create_Ok(GoalIr.ResSel.create_AllOf(_10_ps), _11_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncGrant(g) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(380))), _dafny.Seq.Concat(GoalRender.__default.EncStr((g).dtor_gid), _dafny.Seq.Concat(GoalRender.__default.EncStr((g).dtor_verb), _dafny.Seq.Concat(GoalRender.__default.EncResSel((g).dtor_res), GoalRender.__default.EncCond((g).dtor_cond)))));
    };
    static DecGrant(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(380))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_gid = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecStr(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_verb = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalRender.__default.DecResSel(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_res = (_source2).v;
              let _5_r3 = (_source2).rest;
              let _source3 = GoalRender.__default.DecCondTop(_5_r3);
              {
                if (_source3.is_Fail) {
                  return GoalRender.PR.create_Fail();
                }
              }
              {
                let _6_c = (_source3).v;
                let _7_r4 = (_source3).rest;
                return GoalRender.PR.create_Ok(GoalIr.Grant.create_Grant(_0_gid, _2_verb, _4_res, _6_c), _7_r4);
              }
            }
          }
        }
      }
    };
    static EncProhTarget(t) {
      let _source0 = t;
      {
        if (_source0.is_PVerb) {
          let _0_v = (_source0).verb;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(390))), GoalRender.__default.EncStr(_0_v));
        }
      }
      {
        let _1_c = (_source0).cls;
        return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(391))), GoalRender.__default.EncStr(_1_c));
      }
    };
    static DecProhTarget(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(390))) {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Ok) {
            let _0_v = (_source0).v;
            let _1_r = (_source0).rest;
            return GoalRender.PR.create_Ok(GoalIr.ProhTarget.create_PVerb(_0_v), _1_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(391))) {
        let _source1 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source1.is_Ok) {
            let _2_c = (_source1).v;
            let _3_r = (_source1).rest;
            return GoalRender.PR.create_Ok(GoalIr.ProhTarget.create_PEffect(_2_c), _3_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncProhibit(p) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(392))), _dafny.Seq.Concat(GoalRender.__default.EncStr((p).dtor_pid), _dafny.Seq.Concat(GoalRender.__default.EncProhTarget((p).dtor_target), _dafny.Seq.Concat(GoalRender.__default.EncResSel((p).dtor_res), GoalRender.__default.EncCond((p).dtor_cond)))));
    };
    static DecProhibit(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(392))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_pid = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecProhTarget(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_tg = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalRender.__default.DecResSel(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_res = (_source2).v;
              let _5_r3 = (_source2).rest;
              let _source3 = GoalRender.__default.DecCondTop(_5_r3);
              {
                if (_source3.is_Fail) {
                  return GoalRender.PR.create_Fail();
                }
              }
              {
                let _6_c = (_source3).v;
                let _7_r4 = (_source3).rest;
                return GoalRender.PR.create_Ok(GoalIr.Prohibit.create_Prohibit(_0_pid, _2_tg, _4_res, _6_c), _7_r4);
              }
            }
          }
        }
      }
    };
    static EncAgg(a) {
      let _source0 = a;
      {
        if (_source0.is_ACount) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(400)));
        }
      }
      {
        if (_source0.is_ASum) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(401)));
        }
      }
      {
        if (_source0.is_AMax) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(402)));
        }
      }
      {
        return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(403)));
      }
    };
    static DecAgg(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(400))) {
        return GoalRender.PR.create_Ok(GoalIr.Agg.create_ACount(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(401))) {
        return GoalRender.PR.create_Ok(GoalIr.Agg.create_ASum(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(402))) {
        return GoalRender.PR.create_Ok(GoalIr.Agg.create_AMax(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(403))) {
        return GoalRender.PR.create_Ok(GoalIr.Agg.create_ADistinct(), (ts).slice(_dafny.ONE));
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncSel(s) {
      let _source0 = s;
      {
        if (_source0.is_SelGids) {
          let _0_g = (_source0).gids;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(410))), GoalRender.__default.EncStrs(_0_g));
        }
      }
      {
        let _1_c = (_source0).cls;
        return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(411))), GoalRender.__default.EncStr(_1_c));
      }
    };
    static DecSel(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(410))) {
        let _source0 = GoalRender.__default.DecStrs((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Ok) {
            let _0_g = (_source0).v;
            let _1_r = (_source0).rest;
            return GoalRender.PR.create_Ok(GoalIr.Sel.create_SelGids(_0_g), _1_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(411))) {
        let _source1 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source1.is_Ok) {
            let _2_c = (_source1).v;
            let _3_r = (_source1).rest;
            return GoalRender.PR.create_Ok(GoalIr.Sel.create_SelEffect(_2_c), _3_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncWindow(w) {
      let _source0 = w;
      {
        if (_source0.is_WTask) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(420)));
        }
      }
      {
        if (_source0.is_WSliding) {
          let _0_ms = (_source0).ms;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(421))), GoalRender.__default.EncInt(_0_ms));
        }
      }
      {
        if (_source0.is_WPeriod) {
          let _1_ms = (_source0).ms;
          let _2_t0 = (_source0).t0;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(422))), _dafny.Seq.Concat(GoalRender.__default.EncInt(_1_ms), GoalRender.__default.EncInt(_2_t0)));
        }
      }
      {
        return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(423)));
      }
    };
    static DecWindow(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(420))) {
        return GoalRender.PR.create_Ok(GoalIr.Window.create_WTask(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(421))) {
        let _source0 = GoalRender.__default.DecInt((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Ok) {
            let _0_ms = (_source0).v;
            let _1_r = (_source0).rest;
            return GoalRender.PR.create_Ok(GoalIr.Window.create_WSliding(_0_ms), _1_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(422))) {
        let _source1 = GoalRender.__default.DecInt((ts).slice(_dafny.ONE));
        {
          if (_source1.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _2_ms = (_source1).v;
          let _3_r1 = (_source1).rest;
          let _source2 = GoalRender.__default.DecInt(_3_r1);
          {
            if (_source2.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _4_t0 = (_source2).v;
            let _5_r2 = (_source2).rest;
            return GoalRender.PR.create_Ok(GoalIr.Window.create_WPeriod(_2_ms, _4_t0), _5_r2);
          }
        }
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(423))) {
        return GoalRender.PR.create_Ok(GoalIr.Window.create_WLifetime(), (ts).slice(_dafny.ONE));
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncScope(s) {
      let _source0 = s;
      {
        if (_source0.is_SSession) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(430)));
        }
      }
      {
        if (_source0.is_SPrincipal) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(431)));
        }
      }
      {
        if (_source0.is_SOrg) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(432)));
        }
      }
      {
        let _0_a = (_source0).agents;
        return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(433))), GoalRender.__default.EncStrs(_0_a));
      }
    };
    static DecScope(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(430))) {
        return GoalRender.PR.create_Ok(GoalIr.Scope.create_SSession(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(431))) {
        return GoalRender.PR.create_Ok(GoalIr.Scope.create_SPrincipal(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(432))) {
        return GoalRender.PR.create_Ok(GoalIr.Scope.create_SOrg(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(433))) {
        let _source0 = GoalRender.__default.DecStrs((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Ok) {
            let _0_a = (_source0).v;
            let _1_r = (_source0).rest;
            return GoalRender.PR.create_Ok(GoalIr.Scope.create_SFleet(_0_a), _1_r);
          }
        }
        {
          return GoalRender.PR.create_Fail();
        }
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncOnExceed(o) {
      let _source0 = o;
      {
        if (_source0.is_OnDeny) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(440)));
        }
      }
      {
        return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(441)));
      }
    };
    static DecOnExceed(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!(((ts)[_dafny.ZERO]).is_TKw))) {
        return GoalRender.PR.create_Fail();
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(440))) {
        return GoalRender.PR.create_Ok(GoalIr.OnExceed.create_OnDeny(), (ts).slice(_dafny.ONE));
      } else if ((((ts)[_dafny.ZERO]).dtor_k).isEqualTo(new BigNumber(441))) {
        return GoalRender.PR.create_Ok(GoalIr.OnExceed.create_OnEscalate(), (ts).slice(_dafny.ONE));
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncBCore(b) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(450))), _dafny.Seq.Concat(GoalRender.__default.EncAgg((b).dtor_agg), _dafny.Seq.Concat(GoalRender.__default.EncTerm((b).dtor_value), _dafny.Seq.Concat(GoalRender.__default.EncStr((b).dtor_key), _dafny.Seq.Concat(GoalRender.__default.EncWindow((b).dtor_window), _dafny.Seq.Concat(GoalRender.__default.EncScope((b).dtor_scope), _dafny.Seq.Concat(GoalRender.__default.EncQ((b).dtor_cap), GoalRender.__default.EncOnExceed((b).dtor_onExceed))))))));
    };
    static DecBCore(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(450))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecAgg((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_agg = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecTerm(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_value = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalRender.__default.DecStr(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_key = (_source2).v;
              let _5_r3 = (_source2).rest;
              let _source3 = GoalRender.__default.DecWindow(_5_r3);
              {
                if (_source3.is_Fail) {
                  return GoalRender.PR.create_Fail();
                }
              }
              {
                let _6_window = (_source3).v;
                let _7_r4 = (_source3).rest;
                let _source4 = GoalRender.__default.DecScope(_7_r4);
                {
                  if (_source4.is_Fail) {
                    return GoalRender.PR.create_Fail();
                  }
                }
                {
                  let _8_scope = (_source4).v;
                  let _9_r5 = (_source4).rest;
                  let _source5 = GoalRender.__default.DecQ(_9_r5);
                  {
                    if (_source5.is_Fail) {
                      return GoalRender.PR.create_Fail();
                    }
                  }
                  {
                    let _10_cap = (_source5).v;
                    let _11_r6 = (_source5).rest;
                    let _source6 = GoalRender.__default.DecOnExceed(_11_r6);
                    {
                      if (_source6.is_Fail) {
                        return GoalRender.PR.create_Fail();
                      }
                    }
                    {
                      let _12_oe = (_source6).v;
                      let _13_r7 = (_source6).rest;
                      return GoalRender.PR.create_Ok(GoalIr.BCore.create_BCore(_0_agg, _2_value, _4_key, _6_window, _8_scope, _10_cap, _12_oe), _13_r7);
                    }
                  }
                }
              }
            }
          }
        }
      }
    };
    static EncBound(b) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(451))), _dafny.Seq.Concat(GoalRender.__default.EncStr((b).dtor_bid), _dafny.Seq.Concat(GoalRender.__default.EncSel((b).dtor_sel), GoalRender.__default.EncBCore((b).dtor_core))));
    };
    static DecBound(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(451))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_bid = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecSel(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_sel = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalRender.__default.DecBCore(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_core = (_source2).v;
              let _5_r3 = (_source2).rest;
              return GoalRender.PR.create_Ok(GoalIr.Bound.create_Bound(_0_bid, _2_sel, _4_core), _5_r3);
            }
          }
        }
      }
    };
    static EncValidity(v) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(460))), _dafny.Seq.Concat(GoalRender.__default.EncInt((v).dtor_notBefore), _dafny.Seq.Concat(GoalRender.__default.EncInt((v).dtor_notAfter), GoalRender.__default.EncInt((v).dtor_maxIdle))));
    };
    static DecValidity(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(460))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecInt((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_nb = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecInt(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_na = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalRender.__default.DecInt(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_mi = (_source2).v;
              let _5_r3 = (_source2).rest;
              return GoalRender.PR.create_Ok(GoalIr.Validity.create_Validity(_0_nb, _2_na, _4_mi), _5_r3);
            }
          }
        }
      }
    };
    static EncDeleg(d) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(461))), _dafny.Seq.Concat(GoalRender.__default.EncInt((d).dtor_maxDepth), _dafny.Seq.Concat(GoalRender.__default.EncBool((d).dtor_narrowOnly), GoalRender.__default.EncStrs((d).dtor_mayTouch))));
    };
    static DecDeleg(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(461))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecInt((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_md = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecBool(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_no = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalRender.__default.DecStrs(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_mt = (_source2).v;
              let _5_r3 = (_source2).rest;
              return GoalRender.PR.create_Ok(GoalIr.Delegation.create_Delegation(_0_md, _2_no, _4_mt), _5_r3);
            }
          }
        }
      }
    };
    static EncHole(h) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(470))), _dafny.Seq.Concat(GoalRender.__default.EncStr((h).dtor_hid), _dafny.Seq.Concat(GoalRender.__default.EncStr((h).dtor_q), _dafny.Seq.Concat(GoalRender.__default.EncStrs((h).dtor_domain), _dafny.Seq.Concat(GoalRender.__default.EncStrs((h).dtor_affects), GoalRender.__default.EncBool((h).dtor_global))))));
    };
    static DecHole(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(470))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_hid = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecStr(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_q = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalRender.__default.DecStrs(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_dom = (_source2).v;
              let _5_r3 = (_source2).rest;
              let _source3 = GoalRender.__default.DecStrs(_5_r3);
              {
                if (_source3.is_Fail) {
                  return GoalRender.PR.create_Fail();
                }
              }
              {
                let _6_aff = (_source3).v;
                let _7_r4 = (_source3).rest;
                let _source4 = GoalRender.__default.DecBool(_7_r4);
                {
                  if (_source4.is_Fail) {
                    return GoalRender.PR.create_Fail();
                  }
                }
                {
                  let _8_gl = (_source4).v;
                  let _9_r5 = (_source4).rest;
                  return GoalRender.PR.create_Ok(GoalIr.Hole.create_Hole(_0_hid, _2_q, _4_dom, _6_aff, _8_gl), _9_r5);
                }
              }
            }
          }
        }
      }
    };
    static EncStrsElems(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, GoalRender.__default.EncStr((xs)[_dafny.ZERO]));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static EncStrs(xs) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber((xs).length))), GoalRender.__default.EncStrsElems(xs));
    };
    static DecStrsElems(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Seq.of(), ts);
      } else {
        let _source0 = GoalRender.__default.DecStr(ts);
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_x = (_source0).v;
          let _1_r = (_source0).rest;
          let _source1 = GoalRender.__default.DecStrsElems(_1_r, (n).minus(_dafny.ONE));
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_xs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(_dafny.Seq.Concat(_dafny.Seq.of(_0_x), _2_xs), _3_r2);
          }
        }
      }
    };
    static DecStrs(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalRender.__default.DecStrsElems((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncGrantsElems(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, GoalRender.__default.EncGrant((xs)[_dafny.ZERO]));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static EncGrants(xs) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber((xs).length))), GoalRender.__default.EncGrantsElems(xs));
    };
    static DecGrantsElems(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Seq.of(), ts);
      } else {
        let _source0 = GoalRender.__default.DecGrant(ts);
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_x = (_source0).v;
          let _1_r = (_source0).rest;
          let _source1 = GoalRender.__default.DecGrantsElems(_1_r, (n).minus(_dafny.ONE));
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_xs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(_dafny.Seq.Concat(_dafny.Seq.of(_0_x), _2_xs), _3_r2);
          }
        }
      }
    };
    static DecGrants(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalRender.__default.DecGrantsElems((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncProhibitsElems(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, GoalRender.__default.EncProhibit((xs)[_dafny.ZERO]));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static EncProhibits(xs) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber((xs).length))), GoalRender.__default.EncProhibitsElems(xs));
    };
    static DecProhibitsElems(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Seq.of(), ts);
      } else {
        let _source0 = GoalRender.__default.DecProhibit(ts);
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_x = (_source0).v;
          let _1_r = (_source0).rest;
          let _source1 = GoalRender.__default.DecProhibitsElems(_1_r, (n).minus(_dafny.ONE));
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_xs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(_dafny.Seq.Concat(_dafny.Seq.of(_0_x), _2_xs), _3_r2);
          }
        }
      }
    };
    static DecProhibits(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalRender.__default.DecProhibitsElems((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncBoundsElems(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, GoalRender.__default.EncBound((xs)[_dafny.ZERO]));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static EncBounds(xs) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber((xs).length))), GoalRender.__default.EncBoundsElems(xs));
    };
    static DecBoundsElems(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Seq.of(), ts);
      } else {
        let _source0 = GoalRender.__default.DecBound(ts);
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_x = (_source0).v;
          let _1_r = (_source0).rest;
          let _source1 = GoalRender.__default.DecBoundsElems(_1_r, (n).minus(_dafny.ONE));
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_xs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(_dafny.Seq.Concat(_dafny.Seq.of(_0_x), _2_xs), _3_r2);
          }
        }
      }
    };
    static DecBounds(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalRender.__default.DecBoundsElems((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncCondsElems(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, GoalRender.__default.EncCond((xs)[_dafny.ZERO]));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static EncConds(xs) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber((xs).length))), GoalRender.__default.EncCondsElems(xs));
    };
    static DecCondsElems(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Seq.of(), ts);
      } else {
        let _source0 = GoalRender.__default.DecCondTop(ts);
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_x = (_source0).v;
          let _1_r = (_source0).rest;
          let _source1 = GoalRender.__default.DecCondsElems(_1_r, (n).minus(_dafny.ONE));
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_xs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(_dafny.Seq.Concat(_dafny.Seq.of(_0_x), _2_xs), _3_r2);
          }
        }
      }
    };
    static DecConds(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalRender.__default.DecCondsElems((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncHolesElems(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, GoalRender.__default.EncHole((xs)[_dafny.ZERO]));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static EncHoles(xs) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber((xs).length))), GoalRender.__default.EncHolesElems(xs));
    };
    static DecHolesElems(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Seq.of(), ts);
      } else {
        let _source0 = GoalRender.__default.DecHole(ts);
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_x = (_source0).v;
          let _1_r = (_source0).rest;
          let _source1 = GoalRender.__default.DecHolesElems(_1_r, (n).minus(_dafny.ONE));
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_xs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(_dafny.Seq.Concat(_dafny.Seq.of(_0_x), _2_xs), _3_r2);
          }
        }
      }
    };
    static DecHoles(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalRender.__default.DecHolesElems((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static EncGoal(g) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(480)), GoalRender.Tok.create_TI((g).dtor_v), GoalRender.Tok.create_TS((g).dtor_principal), GoalRender.Tok.create_TS((g).dtor_ontDigest), GoalRender.Tok.create_TS((g).dtor_nlDigest)), _dafny.Seq.Concat(GoalRender.__default.EncStrs((g).dtor_sources), _dafny.Seq.Concat(GoalRender.__default.EncGrants((g).dtor_grants), _dafny.Seq.Concat(GoalRender.__default.EncProhibits((g).dtor_prohibits), _dafny.Seq.Concat(GoalRender.__default.EncBounds((g).dtor_bounds), _dafny.Seq.Concat(GoalRender.__default.EncValidity((g).dtor_validity), _dafny.Seq.Concat(GoalRender.__default.EncDeleg((g).dtor_deleg), _dafny.Seq.Concat(GoalRender.__default.EncConds((g).dtor_escalateOn), _dafny.Seq.Concat(GoalRender.__default.EncStrs((g).dtor_wildcardAck), GoalRender.__default.EncHoles((g).dtor_holes))))))))));
    };
    static DecGoal(ts) {
      if (((((((new BigNumber((ts).length)).isLessThan(new BigNumber(5))) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(480))))) || (!(((ts)[_dafny.ONE]).is_TI))) || (!(((ts)[new BigNumber(2)]).is_TS))) || (!(((ts)[new BigNumber(3)]).is_TS))) || (!(((ts)[new BigNumber(4)]).is_TS))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecStrs((ts).slice(new BigNumber(5)));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_sources = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecGrants(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_grants = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalRender.__default.DecProhibits(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_prohibits = (_source2).v;
              let _5_r3 = (_source2).rest;
              let _source3 = GoalRender.__default.DecBounds(_5_r3);
              {
                if (_source3.is_Fail) {
                  return GoalRender.PR.create_Fail();
                }
              }
              {
                let _6_bounds = (_source3).v;
                let _7_r4 = (_source3).rest;
                let _source4 = GoalRender.__default.DecValidity(_7_r4);
                {
                  if (_source4.is_Fail) {
                    return GoalRender.PR.create_Fail();
                  }
                }
                {
                  let _8_validity = (_source4).v;
                  let _9_r5 = (_source4).rest;
                  let _source5 = GoalRender.__default.DecDeleg(_9_r5);
                  {
                    if (_source5.is_Fail) {
                      return GoalRender.PR.create_Fail();
                    }
                  }
                  {
                    let _10_deleg = (_source5).v;
                    let _11_r6 = (_source5).rest;
                    let _source6 = GoalRender.__default.DecConds(_11_r6);
                    {
                      if (_source6.is_Fail) {
                        return GoalRender.PR.create_Fail();
                      }
                    }
                    {
                      let _12_esc = (_source6).v;
                      let _13_r7 = (_source6).rest;
                      let _source7 = GoalRender.__default.DecStrs(_13_r7);
                      {
                        if (_source7.is_Fail) {
                          return GoalRender.PR.create_Fail();
                        }
                      }
                      {
                        let _14_ack = (_source7).v;
                        let _15_r8 = (_source7).rest;
                        let _source8 = GoalRender.__default.DecHoles(_15_r8);
                        {
                          if (_source8.is_Fail) {
                            return GoalRender.PR.create_Fail();
                          }
                        }
                        {
                          let _16_holes = (_source8).v;
                          let _17_r9 = (_source8).rest;
                          return GoalRender.PR.create_Ok(GoalIr.Goal.create_Goal(((ts)[_dafny.ONE]).dtor_i, ((ts)[new BigNumber(2)]).dtor_s, ((ts)[new BigNumber(3)]).dtor_s, ((ts)[new BigNumber(4)]).dtor_s, _0_sources, _2_grants, _4_prohibits, _6_bounds, _8_validity, _10_deleg, _12_esc, _14_ack, _16_holes), _17_r9);
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    };
    static Render(g) {
      return GoalRender.__default.EncGoal(g);
    };
    static Parse(ts) {
      let _source0 = GoalRender.__default.DecGoal(ts);
      {
        if (_source0.is_Ok) {
          let _0_g = (_source0).v;
          let _1_rest = (_source0).rest;
          if ((new BigNumber((_1_rest).length)).isEqualTo(_dafny.ZERO)) {
            return GoalIr.Option.create_Some(_0_g);
          } else {
            return GoalIr.Option.create_None();
          }
        }
      }
      {
        return GoalIr.Option.create_None();
      }
    };
  };

  $module.Tok = class Tok {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_TKw(k) {
      let $dt = new Tok(0);
      $dt.k = k;
      return $dt;
    }
    static create_TI(i) {
      let $dt = new Tok(1);
      $dt.i = i;
      return $dt;
    }
    static create_TS(s) {
      let $dt = new Tok(2);
      $dt.s = s;
      return $dt;
    }
    get is_TKw() { return this.$tag === 0; }
    get is_TI() { return this.$tag === 1; }
    get is_TS() { return this.$tag === 2; }
    get dtor_k() { return this.k; }
    get dtor_i() { return this.i; }
    get dtor_s() { return this.s; }
    toString() {
      if (this.$tag === 0) {
        return "GoalRender.Tok.TKw" + "(" + _dafny.toString(this.k) + ")";
      } else if (this.$tag === 1) {
        return "GoalRender.Tok.TI" + "(" + _dafny.toString(this.i) + ")";
      } else if (this.$tag === 2) {
        return "GoalRender.Tok.TS" + "(" + this.s.toVerbatimString(true) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.k, other.k);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.i, other.i);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.s, other.s);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalRender.Tok.create_TKw(_dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Tok.Default();
        }
      };
    }
  }

  $module.PR = class PR {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Fail() {
      let $dt = new PR(0);
      return $dt;
    }
    static create_Ok(v, rest) {
      let $dt = new PR(1);
      $dt.v = v;
      $dt.rest = rest;
      return $dt;
    }
    get is_Fail() { return this.$tag === 0; }
    get is_Ok() { return this.$tag === 1; }
    get dtor_v() { return this.v; }
    get dtor_rest() { return this.rest; }
    toString() {
      if (this.$tag === 0) {
        return "GoalRender.PR.Fail";
      } else if (this.$tag === 1) {
        return "GoalRender.PR.Ok" + "(" + _dafny.toString(this.v) + ", " + _dafny.toString(this.rest) + ")";
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
        return other.$tag === 1 && _dafny.areEqual(this.v, other.v) && _dafny.areEqual(this.rest, other.rest);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return GoalRender.PR.create_Fail();
    }
    static Rtd() {
      return class {
        static get Default() {
          return PR.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module GoalRender
let GoalApi = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "GoalApi._default";
    }
    _parentTraits() {
      return [];
    }
    static DecParamDecl(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(500))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_p = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecTy(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_ty = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(GoalIr.ParamDecl.create_ParamDecl(_0_p, _2_ty), _3_r2);
          }
        }
      }
    };
    static DecParamDeclsElems(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Seq.of(), ts);
      } else {
        let _source0 = GoalApi.__default.DecParamDecl(ts);
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_x = (_source0).v;
          let _1_r = (_source0).rest;
          let _source1 = GoalApi.__default.DecParamDeclsElems(_1_r, (n).minus(_dafny.ONE));
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_xs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(_dafny.Seq.Concat(_dafny.Seq.of(_0_x), _2_xs), _3_r2);
          }
        }
      }
    };
    static DecParamDecls(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalApi.__default.DecParamDeclsElems((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static DecVerbDecl(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(501))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_v = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecStr(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_c = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalApi.__default.DecParamDecls(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_ps = (_source2).v;
              let _5_r3 = (_source2).rest;
              return GoalRender.PR.create_Ok(GoalIr.VerbDecl.create_VerbDecl(_0_v, _2_c, _4_ps), _5_r3);
            }
          }
        }
      }
    };
    static DecRelDecl(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(502))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_rel = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecStr(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_an = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalRender.__default.DecStrs(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_ms = (_source2).v;
              let _5_r3 = (_source2).rest;
              return GoalRender.PR.create_Ok(GoalIr.RelDecl.create_RelDecl(_0_rel, _2_an, _4_ms), _5_r3);
            }
          }
        }
      }
    };
    static DecVerbDeclsElems(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Seq.of(), ts);
      } else {
        let _source0 = GoalApi.__default.DecVerbDecl(ts);
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_x = (_source0).v;
          let _1_r = (_source0).rest;
          let _source1 = GoalApi.__default.DecVerbDeclsElems(_1_r, (n).minus(_dafny.ONE));
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_xs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(_dafny.Seq.Concat(_dafny.Seq.of(_0_x), _2_xs), _3_r2);
          }
        }
      }
    };
    static DecVerbDecls(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalApi.__default.DecVerbDeclsElems((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static DecRelDeclsElems(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Seq.of(), ts);
      } else {
        let _source0 = GoalApi.__default.DecRelDecl(ts);
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_x = (_source0).v;
          let _1_r = (_source0).rest;
          let _source1 = GoalApi.__default.DecRelDeclsElems(_1_r, (n).minus(_dafny.ONE));
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_xs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(_dafny.Seq.Concat(_dafny.Seq.of(_0_x), _2_xs), _3_r2);
          }
        }
      }
    };
    static DecRelDecls(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalApi.__default.DecRelDeclsElems((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static DecOntology(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(510))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalApi.__default.DecVerbDecls((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_vs = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalApi.__default.DecRelDecls(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_rs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(GoalIr.Ontology.create_Ontology(_0_vs, _2_rs), _3_r2);
          }
        }
      }
    };
    static DecParamEntries(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Map.Empty.slice(), ts);
      } else if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(520))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_k = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecV(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_v = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalApi.__default.DecParamEntries(_3_r2, (n).minus(_dafny.ONE));
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_m = (_source2).v;
              let _5_r3 = (_source2).rest;
              return GoalRender.PR.create_Ok((_4_m).update(_0_k, _2_v), _5_r3);
            }
          }
        }
      }
    };
    static DecParams(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalApi.__default.DecParamEntries((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static DecAct(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(530))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_verb = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecStr(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_res = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalApi.__default.DecParams(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_ps = (_source2).v;
              let _5_r3 = (_source2).rest;
              let _source3 = GoalRender.__default.DecInt(_5_r3);
              {
                if (_source3.is_Fail) {
                  return GoalRender.PR.create_Fail();
                }
              }
              {
                let _6_t = (_source3).v;
                let _7_r4 = (_source3).rest;
                let _source4 = GoalRender.__default.DecStr(_7_r4);
                {
                  if (_source4.is_Fail) {
                    return GoalRender.PR.create_Fail();
                  }
                }
                {
                  let _8_sess = (_source4).v;
                  let _9_r5 = (_source4).rest;
                  let _source5 = GoalRender.__default.DecStr(_9_r5);
                  {
                    if (_source5.is_Fail) {
                      return GoalRender.PR.create_Fail();
                    }
                  }
                  {
                    let _10_prin = (_source5).v;
                    let _11_r6 = (_source5).rest;
                    let _source6 = GoalRender.__default.DecStr(_11_r6);
                    {
                      if (_source6.is_Fail) {
                        return GoalRender.PR.create_Fail();
                      }
                    }
                    {
                      let _12_org = (_source6).v;
                      let _13_r7 = (_source6).rest;
                      let _source7 = GoalRender.__default.DecStr(_13_r7);
                      {
                        if (_source7.is_Fail) {
                          return GoalRender.PR.create_Fail();
                        }
                      }
                      {
                        let _14_agent = (_source7).v;
                        let _15_r8 = (_source7).rest;
                        let _source8 = GoalRender.__default.DecInt(_15_r8);
                        {
                          if (_source8.is_Fail) {
                            return GoalRender.PR.create_Fail();
                          }
                        }
                        {
                          let _16_depth = (_source8).v;
                          let _17_r9 = (_source8).rest;
                          return GoalRender.PR.create_Ok(GoalIr.Act.create_Act(_0_verb, _2_res, _4_ps, _6_t, _8_sess, _10_prin, _12_org, _14_agent, _16_depth), _17_r9);
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    };
    static DecAdm(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(531))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_gid = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalApi.__default.DecAct(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_a = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(GoalIr.Adm.create_Adm(_0_gid, _2_a), _3_r2);
          }
        }
      }
    };
    static DecAdmsElems(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Seq.of(), ts);
      } else {
        let _source0 = GoalApi.__default.DecAdm(ts);
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_x = (_source0).v;
          let _1_r = (_source0).rest;
          let _source1 = GoalApi.__default.DecAdmsElems(_1_r, (n).minus(_dafny.ONE));
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_xs = (_source1).v;
            let _3_r2 = (_source1).rest;
            return GoalRender.PR.create_Ok(_dafny.Seq.Concat(_dafny.Seq.of(_0_x), _2_xs), _3_r2);
          }
        }
      }
    };
    static DecAdms(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalApi.__default.DecAdmsElems((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static DecAggEntries(ts, n) {
      if ((n).isEqualTo(_dafny.ZERO)) {
        return GoalRender.PR.create_Ok(_dafny.Map.Empty.slice(), ts);
      } else if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(540))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalRender.__default.DecStr((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_k = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecQ(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_q = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalApi.__default.DecAggEntries(_3_r2, (n).minus(_dafny.ONE));
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_m = (_source2).v;
              let _5_r3 = (_source2).rest;
              return GoalRender.PR.create_Ok((_4_m).update(_0_k, _2_q), _5_r3);
            }
          }
        }
      }
    };
    static DecAggs(ts) {
      if ((((_dafny.ZERO).isLessThan(new BigNumber((ts).length))) && (((ts)[_dafny.ZERO]).is_TI)) && ((_dafny.ZERO).isLessThanOrEqualTo(((ts)[_dafny.ZERO]).dtor_i))) {
        return GoalApi.__default.DecAggEntries((ts).slice(_dafny.ONE), ((ts)[_dafny.ZERO]).dtor_i);
      } else {
        return GoalRender.PR.create_Fail();
      }
    };
    static DecHist(ts) {
      if (((new BigNumber((ts).length)).isEqualTo(_dafny.ZERO)) || (!_dafny.areEqual((ts)[_dafny.ZERO], GoalRender.Tok.create_TKw(new BigNumber(541))))) {
        return GoalRender.PR.create_Fail();
      } else {
        let _source0 = GoalApi.__default.DecAdms((ts).slice(_dafny.ONE));
        {
          if (_source0.is_Fail) {
            return GoalRender.PR.create_Fail();
          }
        }
        {
          let _0_adms = (_source0).v;
          let _1_r1 = (_source0).rest;
          let _source1 = GoalRender.__default.DecInt(_1_r1);
          {
            if (_source1.is_Fail) {
              return GoalRender.PR.create_Fail();
            }
          }
          {
            let _2_last = (_source1).v;
            let _3_r2 = (_source1).rest;
            let _source2 = GoalApi.__default.DecAggs(_3_r2);
            {
              if (_source2.is_Fail) {
                return GoalRender.PR.create_Fail();
              }
            }
            {
              let _4_aggs = (_source2).v;
              let _5_r3 = (_source2).rest;
              return GoalRender.PR.create_Ok(GoalIr.Hist.create_Hist(_0_adms, _2_last, _4_aggs), _5_r3);
            }
          }
        }
      }
    };
    static Whole(r) {
      let _source0 = r;
      {
        if (_source0.is_Ok) {
          let _0_v = (_source0).v;
          let _1_rest = (_source0).rest;
          if ((new BigNumber((_1_rest).length)).isEqualTo(_dafny.ZERO)) {
            return GoalIr.Option.create_Some(_0_v);
          } else {
            return GoalIr.Option.create_None();
          }
        }
      }
      {
        return GoalIr.Option.create_None();
      }
    };
    static EncResPat(p) {
      let _source0 = p;
      {
        if (_source0.is_PStar) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(630)));
        }
      }
      {
        let _0_ids = (_source0).ids;
        return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(631))), GoalRender.__default.EncStrs(_0_ids));
      }
    };
    static EncNC(c) {
      let _source0 = c;
      {
        if (_source0.is_NTrue) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(600)));
        }
      }
      {
        if (_source0.is_NFalse) {
          return _dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(601)));
        }
      }
      {
        if (_source0.is_NAtom) {
          let _0_op = (_source0).op;
          let _1_l = (_source0).l;
          let _2_r = (_source0).r;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(602))), _dafny.Seq.Concat(GoalRender.__default.EncOp(_0_op), _dafny.Seq.Concat(GoalRender.__default.EncTerm(_1_l), GoalRender.__default.EncTerm(_2_r))));
        }
      }
      {
        if (_source0.is_NAnd) {
          let _3_x = (_source0).a;
          let _4_y = (_source0).b;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(603))), _dafny.Seq.Concat(GoalApi.__default.EncNC(_3_x), GoalApi.__default.EncNC(_4_y)));
        }
      }
      {
        let _5_x = (_source0).a;
        let _6_y = (_source0).b;
        return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(604))), _dafny.Seq.Concat(GoalApi.__default.EncNC(_5_x), GoalApi.__default.EncNC(_6_y)));
      }
    };
    static EncLPred(p) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(620))), _dafny.Seq.Concat(GoalRender.__default.EncStr((p).dtor_gid), _dafny.Seq.Concat(GoalRender.__default.EncStr((p).dtor_verb), _dafny.Seq.Concat(GoalApi.__default.EncResPat((p).dtor_res), GoalApi.__default.EncNC((p).dtor_cond)))));
    };
    static EncLProh(p) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(640))), _dafny.Seq.Concat(GoalRender.__default.EncStr((p).dtor_pid), _dafny.Seq.Concat(GoalRender.__default.EncStrs((p).dtor_verbs), _dafny.Seq.Concat(GoalApi.__default.EncResPat((p).dtor_res), GoalApi.__default.EncNC((p).dtor_cond)))));
    };
    static EncLCeil(c) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(610))), _dafny.Seq.Concat(GoalRender.__default.EncStr((c).dtor_bid), _dafny.Seq.Concat(GoalRender.__default.EncStrs(((c).dtor_sel).dtor_gids), _dafny.Seq.Concat(GoalRender.__default.EncStrs(((c).dtor_sel).dtor_verbs), GoalRender.__default.EncBCore((c).dtor_core)))));
    };
    static EncLPredsElems(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, GoalApi.__default.EncLPred((xs)[_dafny.ZERO]));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static EncLPreds(xs) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber((xs).length))), GoalApi.__default.EncLPredsElems(xs));
    };
    static EncLProhsElems(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, GoalApi.__default.EncLProh((xs)[_dafny.ZERO]));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static EncLProhs(xs) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber((xs).length))), GoalApi.__default.EncLProhsElems(xs));
    };
    static EncLCeilsElems(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, GoalApi.__default.EncLCeil((xs)[_dafny.ZERO]));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static EncLCeils(xs) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber((xs).length))), GoalApi.__default.EncLCeilsElems(xs));
    };
    static EncNCsElems(xs) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((xs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of());
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, GoalApi.__default.EncNC((xs)[_dafny.ZERO]));
          let _in0 = (xs).slice(_dafny.ONE);
          xs = _in0;
          continue TAIL_CALL_START;
        }
      }
    };
    static EncNCs(xs) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber((xs).length))), GoalApi.__default.EncNCsElems(xs));
    };
    static EncPol(p) {
      return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TKw(new BigNumber(650))), _dafny.Seq.Concat(GoalApi.__default.EncLPreds((p).dtor_preds), _dafny.Seq.Concat(GoalApi.__default.EncLProhs((p).dtor_prohs), _dafny.Seq.Concat(GoalApi.__default.EncLCeils((p).dtor_ceils), _dafny.Seq.Concat(GoalApi.__default.EncNCs((p).dtor_escs), _dafny.Seq.Concat(GoalRender.__default.EncValidity((p).dtor_validity), GoalRender.__default.EncDeleg((p).dtor_deleg)))))));
    };
    static MkKw(k) {
      return GoalRender.Tok.create_TKw(k);
    };
    static MkI(i) {
      return GoalRender.Tok.create_TI(i);
    };
    static MkS(s) {
      return GoalRender.Tok.create_TS(s);
    };
    static TokKind(t) {
      let _source0 = t;
      {
        if (_source0.is_TKw) {
          return _dafny.ZERO;
        }
      }
      {
        if (_source0.is_TI) {
          return _dafny.ONE;
        }
      }
      {
        return new BigNumber(2);
      }
    };
    static TokKw(t) {
      let _source0 = t;
      {
        if (_source0.is_TKw) {
          let _0_k = (_source0).k;
          return _0_k;
        }
      }
      {
        return _dafny.ZERO;
      }
    };
    static TokInt(t) {
      let _source0 = t;
      {
        if (_source0.is_TI) {
          let _0_i = (_source0).i;
          return _0_i;
        }
      }
      {
        return _dafny.ZERO;
      }
    };
    static TokStr(t) {
      let _source0 = t;
      {
        if (_source0.is_TS) {
          let _0_s = (_source0).s;
          return _0_s;
        }
      }
      {
        return _dafny.Seq.UnicodeFromString("");
      }
    };
    static Bad() {
      return _dafny.Seq.of(GoalRender.Tok.create_TI(new BigNumber(9)));
    };
    static ParseG(ts) {
      return GoalRender.__default.Parse(ts);
    };
    static TypecheckT(gt, ot) {
      let _source0 = _dafny.Tuple.of(GoalApi.__default.ParseG(gt), GoalApi.__default.Whole(GoalApi.__default.DecOntology(ot)));
      {
        let _00 = (_source0)[0];
        if (_00.is_Some) {
          let _0_g = (_00).v;
          let _10 = (_source0)[1];
          if (_10.is_Some) {
            let _1_o = (_10).v;
            let _2_rs = GoalCompile.__default.TypeReasons(_1_o, _0_g);
            if ((new BigNumber((_2_rs).length)).isEqualTo(_dafny.ZERO)) {
              return _dafny.Seq.of(GoalRender.Tok.create_TI(_dafny.ZERO));
            } else {
              return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(_dafny.ONE)), GoalRender.__default.EncStrs(_2_rs));
            }
          }
        }
      }
      {
        return GoalApi.__default.Bad();
      }
    };
    static CompileT(gt, ot) {
      let _source0 = _dafny.Tuple.of(GoalApi.__default.ParseG(gt), GoalApi.__default.Whole(GoalApi.__default.DecOntology(ot)));
      {
        let _00 = (_source0)[0];
        if (_00.is_Some) {
          let _0_g = (_00).v;
          let _10 = (_source0)[1];
          if (_10.is_Some) {
            let _1_o = (_10).v;
            let _source1 = GoalCompile.__default.Compile(_1_o, _0_g);
            {
              if (_source1.is_Compiled) {
                let _2_p = (_source1).p;
                return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(_dafny.ZERO)), GoalApi.__default.EncPol(_2_p));
              }
            }
            {
              let _3_rs = (_source1).reasons;
              return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(_dafny.ONE)), GoalRender.__default.EncStrs(_3_rs));
            }
          }
        }
      }
      {
        return GoalApi.__default.Bad();
      }
    };
    static DecideGoalT(gt, ot, at, ht) {
      let _source0 = _dafny.Tuple.of(GoalApi.__default.ParseG(gt), GoalApi.__default.Whole(GoalApi.__default.DecOntology(ot)), GoalApi.__default.Whole(GoalApi.__default.DecAct(at)), GoalApi.__default.Whole(GoalApi.__default.DecHist(ht)));
      {
        let _00 = (_source0)[0];
        if (_00.is_Some) {
          let _0_g = (_00).v;
          let _10 = (_source0)[1];
          if (_10.is_Some) {
            let _1_o = (_10).v;
            let _20 = (_source0)[2];
            if (_20.is_Some) {
              let _2_a = (_20).v;
              let _30 = (_source0)[3];
              if (_30.is_Some) {
                let _3_h = (_30).v;
                return _dafny.Seq.of(GoalRender.Tok.create_TI(_dafny.ZERO), GoalRender.Tok.create_TI(GoalIr.__default.DG(_1_o, _0_g, _2_a, _3_h)));
              }
            }
          }
        }
      }
      {
        return GoalApi.__default.Bad();
      }
    };
    static DecidePolicyT(gt, ot, at, ht) {
      let _source0 = _dafny.Tuple.of(GoalApi.__default.ParseG(gt), GoalApi.__default.Whole(GoalApi.__default.DecOntology(ot)), GoalApi.__default.Whole(GoalApi.__default.DecAct(at)), GoalApi.__default.Whole(GoalApi.__default.DecHist(ht)));
      {
        let _00 = (_source0)[0];
        if (_00.is_Some) {
          let _0_g = (_00).v;
          let _10 = (_source0)[1];
          if (_10.is_Some) {
            let _1_o = (_10).v;
            let _20 = (_source0)[2];
            if (_20.is_Some) {
              let _2_a = (_20).v;
              let _30 = (_source0)[3];
              if (_30.is_Some) {
                let _3_h = (_30).v;
                let _source1 = GoalCompile.__default.Compile(_1_o, _0_g);
                {
                  if (_source1.is_CEscalate) {
                    let _4_rs = (_source1).reasons;
                    return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(_dafny.ONE)), GoalRender.__default.EncStrs(_4_rs));
                  }
                }
                {
                  let _5_p = (_source1).p;
                  let _6_r = GoalWitness.__default.DecideW(_5_p, _2_a, _3_h);
                  return _dafny.Seq.Concat(_dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(_dafny.ZERO), GoalRender.Tok.create_TI((_6_r)[0]), GoalRender.Tok.create_TS(((_6_r)[1]).dtor_gid)), GoalRender.__default.EncStrs(((_6_r)[1]).dtor_bids)), _dafny.Seq.of(GoalRender.Tok.create_TI((((((_6_r)[0]).isEqualTo(GoalIr.__default.Allow)) && (GoalWitness.__default.VerifyWitness(_5_p, _2_a, _3_h, (_6_r)[1]))) ? (_dafny.ONE) : (_dafny.ZERO)))));
                }
              }
            }
          }
        }
      }
      {
        return GoalApi.__default.Bad();
      }
    };
    static RenderT(gt) {
      let _source0 = GoalApi.__default.ParseG(gt);
      {
        if (_source0.is_Some) {
          let _0_g = (_source0).v;
          return _dafny.Seq.Concat(_dafny.Seq.of(GoalRender.Tok.create_TI(_dafny.ZERO)), GoalRender.__default.Render(_0_g));
        }
      }
      {
        return GoalApi.__default.Bad();
      }
    };
  };
  return $module;
})(); // end of module GoalApi
let _module = (function() {
  let $module = {};

  return $module;
})(); // end of module _module

// ---- exports (appended by formal/dafny/build-ext.sh) ----
module.exports = { _dafny, GoalApi };
