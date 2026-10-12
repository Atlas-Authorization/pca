// Dafny program the_program compiled into JavaScript
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
let Common = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Common._default";
    }
    _parentTraits() {
      return [];
    }
    static Get(cs, n) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((cs).length)).isEqualTo(_dafny.ZERO)) {
          return Common.Option.create_None();
        } else if (_dafny.areEqual(((cs)[_dafny.ZERO])[0], n)) {
          return Common.Option.create_Some(((cs)[_dafny.ZERO])[1]);
        } else {
          let _in0 = (cs).slice(_dafny.ONE);
          let _in1 = n;
          cs = _in0;
          n = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static Set(cs, n, s) {
      let _0___accumulator = _dafny.Seq.of();
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((cs).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of(_dafny.Tuple.of(n, s)));
        } else if (_dafny.areEqual(((cs)[_dafny.ZERO])[0], n)) {
          return _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.Concat(_dafny.Seq.of(_dafny.Tuple.of(n, s)), (cs).slice(_dafny.ONE)));
        } else {
          _0___accumulator = _dafny.Seq.Concat(_0___accumulator, _dafny.Seq.of((cs)[_dafny.ZERO]));
          let _in0 = (cs).slice(_dafny.ONE);
          let _in1 = n;
          let _in2 = s;
          cs = _in0;
          n = _in1;
          s = _in2;
          continue TAIL_CALL_START;
        }
      }
    };
    static HasFail(cs) {
      if ((new BigNumber((cs).length)).isEqualTo(_dafny.ZERO)) {
        return false;
      } else {
        return (_dafny.areEqual(((cs)[_dafny.ZERO])[1], Common.Status.create_Fail())) || (Common.__default.HasFail((cs).slice(_dafny.ONE)));
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
        return "Common.Option.None";
      } else if (this.$tag === 1) {
        return "Common.Option.Some" + "(" + _dafny.toString(this.v) + ")";
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
      return Common.Option.create_None();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Option.Default();
        }
      };
    }
  }

  $module.Res = class Res {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Ok() {
      let $dt = new Res(0);
      return $dt;
    }
    static create_Err(m) {
      let $dt = new Res(1);
      $dt.m = m;
      return $dt;
    }
    get is_Ok() { return this.$tag === 0; }
    get is_Err() { return this.$tag === 1; }
    get dtor_m() { return this.m; }
    toString() {
      if (this.$tag === 0) {
        return "Common.Res.Ok";
      } else if (this.$tag === 1) {
        return "Common.Res.Err" + "(" + _dafny.toString(this.m) + ")";
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
        return other.$tag === 1 && _dafny.areEqual(this.m, other.m);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Common.Res.create_Ok();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Res.Default();
        }
      };
    }
  }

  $module.Status = class Status {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Pass() {
      let $dt = new Status(0);
      return $dt;
    }
    static create_Fail() {
      let $dt = new Status(1);
      return $dt;
    }
    static create_NotEnforced() {
      let $dt = new Status(2);
      return $dt;
    }
    get is_Pass() { return this.$tag === 0; }
    get is_Fail() { return this.$tag === 1; }
    get is_NotEnforced() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield Status.create_Pass();
      yield Status.create_Fail();
      yield Status.create_NotEnforced();
    }
    toString() {
      if (this.$tag === 0) {
        return "Common.Status.Pass";
      } else if (this.$tag === 1) {
        return "Common.Status.Fail";
      } else if (this.$tag === 2) {
        return "Common.Status.NotEnforced";
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
      return Common.Status.create_Pass();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Status.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module Common
let Chain = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Chain._default";
    }
    _parentTraits() {
      return [];
    }
    static FirstAltered(p, c, ceq, from) {
      TAIL_CALL_START: while (true) {
        if ((from).isEqualTo(new BigNumber((p).length))) {
          return Common.Option.create_None();
        } else if (!((ceq)((c)[from], (p)[from]))) {
          return Common.Option.create_Some(from);
        } else {
          let _in0 = p;
          let _in1 = c;
          let _in2 = ceq;
          let _in3 = (from).plus(_dafny.ONE);
          p = _in0;
          c = _in1;
          ceq = _in2;
          from = _in3;
          continue TAIL_CALL_START;
        }
      }
    };
    static PrefixCheck(hop, p, c, ceq) {
      if ((new BigNumber((c).length)).isLessThan(new BigNumber((p).length))) {
        return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_Drops(hop));
      } else {
        let _source0 = Chain.__default.FirstAltered(p, c, ceq, _dafny.ZERO);
        {
          if (_source0.is_Some) {
            let _0_j = (_source0).v;
            return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_Altered(hop, _0_j));
          }
        }
        {
          return Chain.ChainResult.create_ChainOk();
        }
      }
    };
    static RootCheck(h) {
      if ((h).dtor_hasParent) {
        return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_RootHasParent());
      } else if (!((h).dtor_rootIssuerOk)) {
        return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_RootIssuer());
      } else {
        let _source0 = ((h).dtor_suite)();
        {
          if (_source0.is_Err) {
            let _0_m = (_source0).m;
            return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_SuiteErr(_dafny.ZERO, _0_m));
          }
        }
        {
          let _source1 = ((h).dtor_pq)();
          {
            if (_source1.is_Err) {
              let _1_m = (_source1).m;
              return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_PqErr(_dafny.ZERO, _1_m));
            }
          }
          {
            let _source2 = ((h).dtor_sig)();
            {
              if (_source2.is_Err) {
                let _2_m = (_source2).m;
                return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_SigErr(_dafny.ZERO, _2_m));
              }
            }
            {
              return Chain.ChainResult.create_ChainOk();
            }
          }
        }
      }
    };
    static HopCheck(i, parent, c, ceq) {
      if (!(((c).dtor_parentLinkOk)())) {
        return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_ParentLink(i));
      } else if (!(((c).dtor_issuerIsParentHolder)())) {
        return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_IssuerNotHolder(i));
      } else {
        let _source0 = ((c).dtor_suite)();
        {
          if (_source0.is_Err) {
            let _0_m = (_source0).m;
            return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_SuiteErr(i, _0_m));
          }
        }
        {
          let _source1 = ((c).dtor_pq)();
          {
            if (_source1.is_Err) {
              let _1_m = (_source1).m;
              return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_PqErr(i, _1_m));
            }
          }
          {
            let _source2 = ((c).dtor_sig)();
            {
              if (_source2.is_Err) {
                let _2_m = (_source2).m;
                return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_SigErr(i, _2_m));
              }
            }
            {
              return Chain.__default.PrefixCheck(i, (parent).dtor_caveats, (c).dtor_caveats, ceq);
            }
          }
        }
      }
    };
    static FirstMalformed(hops, from) {
      TAIL_CALL_START: while (true) {
        if ((from).isEqualTo(new BigNumber((hops).length))) {
          return Common.Option.create_None();
        } else if (!(((hops)[from]).dtor_wellTyped)) {
          return Common.Option.create_Some(from);
        } else {
          let _in0 = hops;
          let _in1 = (from).plus(_dafny.ONE);
          hops = _in0;
          from = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static Walk(hops, ceq, alloc, i) {
      TAIL_CALL_START: while (true) {
        if ((i).isEqualTo(new BigNumber((hops).length))) {
          let _source0 = (alloc)();
          {
            if (_source0.is_Err) {
              let _0_m = (_source0).m;
              return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_Alloc(_0_m));
            }
          }
          {
            return Chain.ChainResult.create_ChainOk();
          }
        } else {
          let _source1 = Chain.__default.HopCheck(i, (hops)[(i).minus(_dafny.ONE)], (hops)[i], ceq);
          {
            if (_source1.is_ChainBad) {
              let _1_e = (_source1).e;
              return Chain.ChainResult.create_ChainBad(_1_e);
            }
          }
          {
            let _in0 = hops;
            let _in1 = ceq;
            let _in2 = alloc;
            let _in3 = (i).plus(_dafny.ONE);
            hops = _in0;
            ceq = _in1;
            alloc = _in2;
            i = _in3;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static VerifyChain(hops, ceq, alloc) {
      if ((new BigNumber((hops).length)).isEqualTo(_dafny.ZERO)) {
        return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_Empty());
      } else if ((Chain.__default.MaxDepth).isLessThan(new BigNumber((hops).length))) {
        return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_TooLong());
      } else {
        let _source0 = Chain.__default.FirstMalformed(hops, _dafny.ZERO);
        {
          if (_source0.is_Some) {
            let _0_i = (_source0).v;
            return Chain.ChainResult.create_ChainBad(Chain.ChainErr.create_Malformed(_0_i));
          }
        }
        {
          let _source1 = Chain.__default.RootCheck((hops)[_dafny.ZERO]);
          {
            if (_source1.is_ChainBad) {
              let _1_e = (_source1).e;
              return Chain.ChainResult.create_ChainBad(_1_e);
            }
          }
          {
            return Chain.__default.Walk(hops, ceq, alloc, _dafny.ONE);
          }
        }
      }
    };
    static get MaxDepth() {
      return new BigNumber(16);
    };
  };

  $module.Hop = class Hop {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Hop(wellTyped, hasParent, rootIssuerOk, caveats, parentLinkOk, issuerIsParentHolder, suite, pq, sig) {
      let $dt = new Hop(0);
      $dt.wellTyped = wellTyped;
      $dt.hasParent = hasParent;
      $dt.rootIssuerOk = rootIssuerOk;
      $dt.caveats = caveats;
      $dt.parentLinkOk = parentLinkOk;
      $dt.issuerIsParentHolder = issuerIsParentHolder;
      $dt.suite = suite;
      $dt.pq = pq;
      $dt.sig = sig;
      return $dt;
    }
    get is_Hop() { return this.$tag === 0; }
    get dtor_wellTyped() { return this.wellTyped; }
    get dtor_hasParent() { return this.hasParent; }
    get dtor_rootIssuerOk() { return this.rootIssuerOk; }
    get dtor_caveats() { return this.caveats; }
    get dtor_parentLinkOk() { return this.parentLinkOk; }
    get dtor_issuerIsParentHolder() { return this.issuerIsParentHolder; }
    get dtor_suite() { return this.suite; }
    get dtor_pq() { return this.pq; }
    get dtor_sig() { return this.sig; }
    toString() {
      if (this.$tag === 0) {
        return "Chain.Hop.Hop" + "(" + _dafny.toString(this.wellTyped) + ", " + _dafny.toString(this.hasParent) + ", " + _dafny.toString(this.rootIssuerOk) + ", " + _dafny.toString(this.caveats) + ", " + _dafny.toString(this.parentLinkOk) + ", " + _dafny.toString(this.issuerIsParentHolder) + ", " + _dafny.toString(this.suite) + ", " + _dafny.toString(this.pq) + ", " + _dafny.toString(this.sig) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.wellTyped === other.wellTyped && this.hasParent === other.hasParent && this.rootIssuerOk === other.rootIssuerOk && _dafny.areEqual(this.caveats, other.caveats) && _dafny.areEqual(this.parentLinkOk, other.parentLinkOk) && _dafny.areEqual(this.issuerIsParentHolder, other.issuerIsParentHolder) && _dafny.areEqual(this.suite, other.suite) && _dafny.areEqual(this.pq, other.pq) && _dafny.areEqual(this.sig, other.sig);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Chain.Hop.create_Hop(false, false, false, _dafny.Seq.of(), function () { return false; }, function () { return false; }, function () { return Common.Res.Default(); }, function () { return Common.Res.Default(); }, function () { return Common.Res.Default(); });
    }
    static Rtd() {
      return class {
        static get Default() {
          return Hop.Default();
        }
      };
    }
  }

  $module.ChainErr = class ChainErr {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Empty() {
      let $dt = new ChainErr(0);
      return $dt;
    }
    static create_TooLong() {
      let $dt = new ChainErr(1);
      return $dt;
    }
    static create_Malformed(hop) {
      let $dt = new ChainErr(2);
      $dt.hop = hop;
      return $dt;
    }
    static create_RootHasParent() {
      let $dt = new ChainErr(3);
      return $dt;
    }
    static create_RootIssuer() {
      let $dt = new ChainErr(4);
      return $dt;
    }
    static create_SuiteErr(hop, m) {
      let $dt = new ChainErr(5);
      $dt.hop = hop;
      $dt.m = m;
      return $dt;
    }
    static create_PqErr(hop, m) {
      let $dt = new ChainErr(6);
      $dt.hop = hop;
      $dt.m = m;
      return $dt;
    }
    static create_SigErr(hop, m) {
      let $dt = new ChainErr(7);
      $dt.hop = hop;
      $dt.m = m;
      return $dt;
    }
    static create_ParentLink(hop) {
      let $dt = new ChainErr(8);
      $dt.hop = hop;
      return $dt;
    }
    static create_IssuerNotHolder(hop) {
      let $dt = new ChainErr(9);
      $dt.hop = hop;
      return $dt;
    }
    static create_Drops(hop) {
      let $dt = new ChainErr(10);
      $dt.hop = hop;
      return $dt;
    }
    static create_Altered(hop, j) {
      let $dt = new ChainErr(11);
      $dt.hop = hop;
      $dt.j = j;
      return $dt;
    }
    static create_Alloc(m) {
      let $dt = new ChainErr(12);
      $dt.m = m;
      return $dt;
    }
    get is_Empty() { return this.$tag === 0; }
    get is_TooLong() { return this.$tag === 1; }
    get is_Malformed() { return this.$tag === 2; }
    get is_RootHasParent() { return this.$tag === 3; }
    get is_RootIssuer() { return this.$tag === 4; }
    get is_SuiteErr() { return this.$tag === 5; }
    get is_PqErr() { return this.$tag === 6; }
    get is_SigErr() { return this.$tag === 7; }
    get is_ParentLink() { return this.$tag === 8; }
    get is_IssuerNotHolder() { return this.$tag === 9; }
    get is_Drops() { return this.$tag === 10; }
    get is_Altered() { return this.$tag === 11; }
    get is_Alloc() { return this.$tag === 12; }
    get dtor_hop() { return this.hop; }
    get dtor_m() { return this.m; }
    get dtor_j() { return this.j; }
    toString() {
      if (this.$tag === 0) {
        return "Chain.ChainErr.Empty";
      } else if (this.$tag === 1) {
        return "Chain.ChainErr.TooLong";
      } else if (this.$tag === 2) {
        return "Chain.ChainErr.Malformed" + "(" + _dafny.toString(this.hop) + ")";
      } else if (this.$tag === 3) {
        return "Chain.ChainErr.RootHasParent";
      } else if (this.$tag === 4) {
        return "Chain.ChainErr.RootIssuer";
      } else if (this.$tag === 5) {
        return "Chain.ChainErr.SuiteErr" + "(" + _dafny.toString(this.hop) + ", " + _dafny.toString(this.m) + ")";
      } else if (this.$tag === 6) {
        return "Chain.ChainErr.PqErr" + "(" + _dafny.toString(this.hop) + ", " + _dafny.toString(this.m) + ")";
      } else if (this.$tag === 7) {
        return "Chain.ChainErr.SigErr" + "(" + _dafny.toString(this.hop) + ", " + _dafny.toString(this.m) + ")";
      } else if (this.$tag === 8) {
        return "Chain.ChainErr.ParentLink" + "(" + _dafny.toString(this.hop) + ")";
      } else if (this.$tag === 9) {
        return "Chain.ChainErr.IssuerNotHolder" + "(" + _dafny.toString(this.hop) + ")";
      } else if (this.$tag === 10) {
        return "Chain.ChainErr.Drops" + "(" + _dafny.toString(this.hop) + ")";
      } else if (this.$tag === 11) {
        return "Chain.ChainErr.Altered" + "(" + _dafny.toString(this.hop) + ", " + _dafny.toString(this.j) + ")";
      } else if (this.$tag === 12) {
        return "Chain.ChainErr.Alloc" + "(" + _dafny.toString(this.m) + ")";
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
        return other.$tag === 2 && _dafny.areEqual(this.hop, other.hop);
      } else if (this.$tag === 3) {
        return other.$tag === 3;
      } else if (this.$tag === 4) {
        return other.$tag === 4;
      } else if (this.$tag === 5) {
        return other.$tag === 5 && _dafny.areEqual(this.hop, other.hop) && _dafny.areEqual(this.m, other.m);
      } else if (this.$tag === 6) {
        return other.$tag === 6 && _dafny.areEqual(this.hop, other.hop) && _dafny.areEqual(this.m, other.m);
      } else if (this.$tag === 7) {
        return other.$tag === 7 && _dafny.areEqual(this.hop, other.hop) && _dafny.areEqual(this.m, other.m);
      } else if (this.$tag === 8) {
        return other.$tag === 8 && _dafny.areEqual(this.hop, other.hop);
      } else if (this.$tag === 9) {
        return other.$tag === 9 && _dafny.areEqual(this.hop, other.hop);
      } else if (this.$tag === 10) {
        return other.$tag === 10 && _dafny.areEqual(this.hop, other.hop);
      } else if (this.$tag === 11) {
        return other.$tag === 11 && _dafny.areEqual(this.hop, other.hop) && _dafny.areEqual(this.j, other.j);
      } else if (this.$tag === 12) {
        return other.$tag === 12 && _dafny.areEqual(this.m, other.m);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Chain.ChainErr.create_Empty();
    }
    static Rtd() {
      return class {
        static get Default() {
          return ChainErr.Default();
        }
      };
    }
  }

  $module.ChainResult = class ChainResult {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_ChainOk() {
      let $dt = new ChainResult(0);
      return $dt;
    }
    static create_ChainBad(e) {
      let $dt = new ChainResult(1);
      $dt.e = e;
      return $dt;
    }
    get is_ChainOk() { return this.$tag === 0; }
    get is_ChainBad() { return this.$tag === 1; }
    get dtor_e() { return this.e; }
    toString() {
      if (this.$tag === 0) {
        return "Chain.ChainResult.ChainOk";
      } else if (this.$tag === 1) {
        return "Chain.ChainResult.ChainBad" + "(" + _dafny.toString(this.e) + ")";
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
        return other.$tag === 1 && _dafny.areEqual(this.e, other.e);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Chain.ChainResult.create_ChainOk();
    }
    static Rtd() {
      return class {
        static get Default() {
          return ChainResult.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module Chain
let Caveats = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Caveats._default";
    }
    _parentTraits() {
      return [];
    }
    static Allows(c, a) {
      let _source0 = c;
      {
        if (_source0.is_VerbIn) {
          let _0_vs = (_source0).verbs;
          return (_0_vs).contains((a).dtor_verb);
        }
      }
      {
        if (_source0.is_ResIn) {
          let _1_rs = (_source0).resources;
          return (_1_rs).contains((a).dtor_resource);
        }
      }
      {
        if (_source0.is_ExpiresAt) {
          let _2_t = (_source0).t;
          return ((a).dtor_now).isLessThanOrEqualTo(_2_t);
        }
      }
      {
        return true;
      }
    };
    static Same(x, y) {
      return _dafny.areEqual(x, y);
    };
    static MinOpt(a, b) {
      let _source0 = a;
      {
        if (_source0.is_None) {
          return b;
        }
      }
      {
        let _0_x = (_source0).v;
        let _source1 = b;
        {
          if (_source1.is_None) {
            return a;
          }
        }
        {
          let _1_y = (_source1).v;
          if ((_0_x).isLessThanOrEqualTo(_1_y)) {
            return a;
          } else {
            return b;
          }
        }
      }
    };
    static EffExpiry(cs) {
      if ((new BigNumber((cs).length)).isEqualTo(_dafny.ZERO)) {
        return Common.Option.create_None();
      } else {
        return Caveats.__default.MinOpt(function () {
          let _source0 = (cs)[_dafny.ZERO];
          {
            if (_source0.is_ExpiresAt) {
              let _0_t = (_source0).t;
              return Common.Option.create_Some(_0_t);
            }
          }
          {
            return Common.Option.create_None();
          }
        }(), Caveats.__default.EffExpiry((cs).slice(_dafny.ONE)));
      }
    };
    static NoLater(a, b) {
      let _source0 = b;
      {
        if (_source0.is_None) {
          return true;
        }
      }
      {
        let _0_y = (_source0).v;
        return ((a).is_Some) && (((a).dtor_v).isLessThanOrEqualTo(_0_y));
      }
    };
  };

  $module.Caveat = class Caveat {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_VerbIn(verbs) {
      let $dt = new Caveat(0);
      $dt.verbs = verbs;
      return $dt;
    }
    static create_ResIn(resources) {
      let $dt = new Caveat(1);
      $dt.resources = resources;
      return $dt;
    }
    static create_ExpiresAt(t) {
      let $dt = new Caveat(2);
      $dt.t = t;
      return $dt;
    }
    static create_Opaque(id) {
      let $dt = new Caveat(3);
      $dt.id = id;
      return $dt;
    }
    get is_VerbIn() { return this.$tag === 0; }
    get is_ResIn() { return this.$tag === 1; }
    get is_ExpiresAt() { return this.$tag === 2; }
    get is_Opaque() { return this.$tag === 3; }
    get dtor_verbs() { return this.verbs; }
    get dtor_resources() { return this.resources; }
    get dtor_t() { return this.t; }
    get dtor_id() { return this.id; }
    toString() {
      if (this.$tag === 0) {
        return "Caveats.Caveat.VerbIn" + "(" + _dafny.toString(this.verbs) + ")";
      } else if (this.$tag === 1) {
        return "Caveats.Caveat.ResIn" + "(" + _dafny.toString(this.resources) + ")";
      } else if (this.$tag === 2) {
        return "Caveats.Caveat.ExpiresAt" + "(" + _dafny.toString(this.t) + ")";
      } else if (this.$tag === 3) {
        return "Caveats.Caveat.Opaque" + "(" + this.id.toVerbatimString(true) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.verbs, other.verbs);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.resources, other.resources);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.t, other.t);
      } else if (this.$tag === 3) {
        return other.$tag === 3 && _dafny.areEqual(this.id, other.id);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Caveats.Caveat.create_VerbIn(_dafny.Set.Empty);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Caveat.Default();
        }
      };
    }
  }

  $module.Act = class Act {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Act(verb, resource, now) {
      let $dt = new Act(0);
      $dt.verb = verb;
      $dt.resource = resource;
      $dt.now = now;
      return $dt;
    }
    get is_Act() { return this.$tag === 0; }
    get dtor_verb() { return this.verb; }
    get dtor_resource() { return this.resource; }
    get dtor_now() { return this.now; }
    toString() {
      if (this.$tag === 0) {
        return "Caveats.Act.Act" + "(" + this.verb.toVerbatimString(true) + ", " + this.resource.toVerbatimString(true) + ", " + _dafny.toString(this.now) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.verb, other.verb) && _dafny.areEqual(this.resource, other.resource) && _dafny.areEqual(this.now, other.now);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Caveats.Act.create_Act(_dafny.Seq.UnicodeFromString(""), _dafny.Seq.UnicodeFromString(""), _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Act.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module Caveats
let Threshold = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Threshold._default";
    }
    _parentTraits() {
      return [];
    }
    static ValidT(t) {
      return (((t).isEqualTo(_dafny.ONE)) || ((t).isEqualTo(new BigNumber(2)))) || ((t).isEqualTo(new BigNumber(3)));
    };
    static LookupKey(reg, r) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((reg).length)).isEqualTo(_dafny.ZERO)) {
          return Common.Option.create_None();
        } else if (_dafny.areEqual(((reg)[_dafny.ZERO])[0], r)) {
          return Common.Option.create_Some(((reg)[_dafny.ZERO])[1]);
        } else {
          let _in0 = (reg).slice(_dafny.ONE);
          let _in1 = r;
          reg = _in0;
          r = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static LookupRole(reg, k) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((reg).length)).isEqualTo(_dafny.ZERO)) {
          return Common.Option.create_None();
        } else if (_dafny.areEqual(((reg)[_dafny.ZERO])[1], k)) {
          return Common.Option.create_Some(((reg)[_dafny.ZERO])[0]);
        } else {
          let _in0 = (reg).slice(_dafny.ONE);
          let _in1 = k;
          reg = _in0;
          k = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static BuildReg(es, from, reg) {
      TAIL_CALL_START: while (true) {
        if ((from).isEqualTo(new BigNumber((es).length))) {
          return Threshold.RegResult.create_RegOk(reg);
        } else {
          let _0_e = (es)[from];
          if (!((((_0_e).dtor_role).is_Some) && ((_0_e).dtor_keyOk))) {
            return Threshold.RegResult.create_RegBad(Threshold.ThReason.create_SetMalformed());
          } else if (!((_0_e).dtor_pqOk)) {
            return Threshold.RegResult.create_RegBad(Threshold.ThReason.create_SetPq());
          } else {
            let _1_r = ((_0_e).dtor_role).dtor_v;
            let _2_prevKey = Threshold.__default.LookupKey(reg, _1_r);
            if (((_2_prevKey).is_Some) && (!_dafny.areEqual((_2_prevKey).dtor_v, (_0_e).dtor_key))) {
              return Threshold.RegResult.create_RegBad(Threshold.ThReason.create_TwoKeysForRole(from));
            } else {
              let _3_prevRole = Threshold.__default.LookupRole(reg, (_0_e).dtor_key);
              if (((_3_prevRole).is_Some) && (!_dafny.areEqual((_3_prevRole).dtor_v, _1_r))) {
                return Threshold.RegResult.create_RegBad(Threshold.ThReason.create_OneKeyTwoRoles());
              } else {
                let _in0 = es;
                let _in1 = (from).plus(_dafny.ONE);
                let _in2 = (((_2_prevKey).is_Some) ? (reg) : (_dafny.Seq.Concat(reg, _dafny.Seq.of(_dafny.Tuple.of(_1_r, (_0_e).dtor_key)))));
                es = _in0;
                from = _in1;
                reg = _in2;
                continue TAIL_CALL_START;
              }
            }
          }
        }
      }
    };
    static First(a, b) {
      if ((a).is_Some) {
        return a;
      } else {
        return Common.Option.create_Some(b);
      }
    };
    static Contains(ks, k) {
      return _dafny.Quantifier(_dafny.IntegerRange(_dafny.ZERO, new BigNumber((ks).length)), false, function (_exists_var_0) {
        let _0_i = _exists_var_0;
        return (((_dafny.ZERO).isLessThanOrEqualTo(_0_i)) && ((_0_i).isLessThan(new BigNumber((ks).length)))) && (_dafny.areEqual((ks)[_0_i], k));
      });
    };
    static ContainsB(ks, k) {
      return ((_dafny.ZERO).isLessThan(new BigNumber((ks).length))) && ((_dafny.areEqual((ks)[_dafny.ZERO], k)) || (Threshold.__default.ContainsB((ks).slice(_dafny.ONE), k)));
    };
    static Step(reg, i, sh, st) {
      if (!((sh).dtor_wellFormed)) {
        return Threshold.St.create_St((st).dtor_keys, (st).dtor_roles, Threshold.__default.First((st).dtor_reason, Threshold.ThReason.create_MalformedShare()));
      } else if (Threshold.__default.ContainsB((st).dtor_keys, (sh).dtor_key)) {
        return st;
      } else {
        let _0_rk = ((((sh).dtor_role).is_Some) ? (Threshold.__default.LookupKey(reg, ((sh).dtor_role).dtor_v)) : (Common.Option.create_None()));
        if ((_0_rk).is_None) {
          return Threshold.St.create_St((st).dtor_keys, (st).dtor_roles, Threshold.__default.First((st).dtor_reason, Threshold.ThReason.create_RoleNotInSet(i)));
        } else if (!_dafny.areEqual((_0_rk).dtor_v, (sh).dtor_key)) {
          return Threshold.St.create_St((st).dtor_keys, (st).dtor_roles, Threshold.__default.First((st).dtor_reason, Threshold.ThReason.create_KeyNotRegistered(i)));
        } else if (!((sh).dtor_algKnown)) {
          return Threshold.St.create_St((st).dtor_keys, (st).dtor_roles, Threshold.__default.First((st).dtor_reason, Threshold.ThReason.create_UnknownAlg(i)));
        } else if (!((sh).dtor_pqPkOk)) {
          return Threshold.St.create_St((st).dtor_keys, (st).dtor_roles, Threshold.__default.First((st).dtor_reason, Threshold.ThReason.create_PqPkMismatch(i)));
        } else if (!(((sh).dtor_sigOk)())) {
          return Threshold.St.create_St((st).dtor_keys, (st).dtor_roles, Threshold.__default.First((st).dtor_reason, Threshold.ThReason.create_InvalidSig(i)));
        } else {
          return Threshold.St.create_St(_dafny.Seq.Concat((st).dtor_keys, _dafny.Seq.of((sh).dtor_key)), _dafny.Seq.Concat((st).dtor_roles, _dafny.Seq.of(((sh).dtor_role).dtor_v)), (st).dtor_reason);
        }
      }
    };
    static Fold(reg, shares, i, st) {
      TAIL_CALL_START: while (true) {
        if ((i).isEqualTo(new BigNumber((shares).length))) {
          return st;
        } else {
          let _in0 = reg;
          let _in1 = shares;
          let _in2 = (i).plus(_dafny.ONE);
          let _in3 = Threshold.__default.Step(reg, i, (shares)[i], st);
          reg = _in0;
          shares = _in1;
          i = _in2;
          st = _in3;
          continue TAIL_CALL_START;
        }
      }
    };
    static BaselineStep(reg, b, st) {
      if ((b).is_None) {
        return st;
      } else {
        let _0_bl = (b).dtor_v;
        let _1_agentKey = Threshold.__default.LookupKey(reg, Threshold.Role.create_Agent());
        if (((((((_0_bl).dtor_holderIsString) && ((_1_agentKey).is_Some)) && (_dafny.areEqual((_0_bl).dtor_holder, (_1_agentKey).dtor_v))) && (!(Threshold.__default.ContainsB((st).dtor_keys, (_1_agentKey).dtor_v)))) && (((_0_bl).dtor_pqKeyOk)())) && (((_0_bl).dtor_leafSigOk)())) {
          return Threshold.St.create_St(_dafny.Seq.Concat((st).dtor_keys, _dafny.Seq.of((_1_agentKey).dtor_v)), _dafny.Seq.Concat((st).dtor_roles, _dafny.Seq.of(Threshold.Role.create_Agent())), (st).dtor_reason);
        } else {
          return st;
        }
      }
    };
    static Verify(es, shares, t, baseline) {
      if (!(Threshold.__default.ValidT(t))) {
        return Threshold.ThVerdict.create_ThVerdict(false, _dafny.ZERO, _dafny.Seq.of(), Common.Option.create_Some(Threshold.ThReason.create_InvalidT()));
      } else {
        let _source0 = Threshold.__default.BuildReg(es, _dafny.ZERO, _dafny.Seq.of());
        {
          if (_source0.is_RegBad) {
            let _0_r = (_source0).r;
            return Threshold.ThVerdict.create_ThVerdict(false, _dafny.ZERO, _dafny.Seq.of(), Common.Option.create_Some(_0_r));
          }
        }
        {
          let _1_reg = (_source0).reg;
          let _2_st = Threshold.__default.BaselineStep(_1_reg, baseline, Threshold.__default.Fold(_1_reg, shares, _dafny.ZERO, Threshold.St.create_St(_dafny.Seq.of(), _dafny.Seq.of(), Common.Option.create_None())));
          let _3_count = new BigNumber(((_2_st).dtor_keys).length);
          if ((t).isLessThanOrEqualTo(_3_count)) {
            return Threshold.ThVerdict.create_ThVerdict(true, _3_count, (_2_st).dtor_roles, Common.Option.create_None());
          } else {
            return Threshold.ThVerdict.create_ThVerdict(false, _3_count, (_2_st).dtor_roles, ((((_2_st).dtor_reason).is_Some) ? ((_2_st).dtor_reason) : (Common.Option.create_Some(Threshold.ThReason.create_NeedMore()))));
          }
        }
      }
    };
    static get AllRoles() {
      return _dafny.Set.fromElements(Threshold.Role.create_Agent(), Threshold.Role.create_Guardian(), Threshold.Role.create_Principal());
    };
  };

  $module.Role = class Role {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Agent() {
      let $dt = new Role(0);
      return $dt;
    }
    static create_Guardian() {
      let $dt = new Role(1);
      return $dt;
    }
    static create_Principal() {
      let $dt = new Role(2);
      return $dt;
    }
    get is_Agent() { return this.$tag === 0; }
    get is_Guardian() { return this.$tag === 1; }
    get is_Principal() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield Role.create_Agent();
      yield Role.create_Guardian();
      yield Role.create_Principal();
    }
    toString() {
      if (this.$tag === 0) {
        return "Threshold.Role.Agent";
      } else if (this.$tag === 1) {
        return "Threshold.Role.Guardian";
      } else if (this.$tag === 2) {
        return "Threshold.Role.Principal";
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
      return Threshold.Role.create_Agent();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Role.Default();
        }
      };
    }
  }

  $module.Signer = class Signer {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Signer(role, keyOk, pqOk, key) {
      let $dt = new Signer(0);
      $dt.role = role;
      $dt.keyOk = keyOk;
      $dt.pqOk = pqOk;
      $dt.key = key;
      return $dt;
    }
    get is_Signer() { return this.$tag === 0; }
    get dtor_role() { return this.role; }
    get dtor_keyOk() { return this.keyOk; }
    get dtor_pqOk() { return this.pqOk; }
    get dtor_key() { return this.key; }
    toString() {
      if (this.$tag === 0) {
        return "Threshold.Signer.Signer" + "(" + _dafny.toString(this.role) + ", " + _dafny.toString(this.keyOk) + ", " + _dafny.toString(this.pqOk) + ", " + _dafny.toString(this.key) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.role, other.role) && this.keyOk === other.keyOk && this.pqOk === other.pqOk && _dafny.areEqual(this.key, other.key);
      } else  {
        return false; // unexpected
      }
    }
    static Default(_default_K) {
      return Threshold.Signer.create_Signer(Common.Option.Default(), false, false, _default_K);
    }
    static Rtd(rtd$_K) {
      return class {
        static get Default() {
          return Signer.Default(rtd$_K.Default);
        }
      };
    }
  }

  $module.Share = class Share {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Share(wellFormed, role, key, algKnown, pqPkOk, sigOk) {
      let $dt = new Share(0);
      $dt.wellFormed = wellFormed;
      $dt.role = role;
      $dt.key = key;
      $dt.algKnown = algKnown;
      $dt.pqPkOk = pqPkOk;
      $dt.sigOk = sigOk;
      return $dt;
    }
    get is_Share() { return this.$tag === 0; }
    get dtor_wellFormed() { return this.wellFormed; }
    get dtor_role() { return this.role; }
    get dtor_key() { return this.key; }
    get dtor_algKnown() { return this.algKnown; }
    get dtor_pqPkOk() { return this.pqPkOk; }
    get dtor_sigOk() { return this.sigOk; }
    toString() {
      if (this.$tag === 0) {
        return "Threshold.Share.Share" + "(" + _dafny.toString(this.wellFormed) + ", " + _dafny.toString(this.role) + ", " + _dafny.toString(this.key) + ", " + _dafny.toString(this.algKnown) + ", " + _dafny.toString(this.pqPkOk) + ", " + _dafny.toString(this.sigOk) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.wellFormed === other.wellFormed && _dafny.areEqual(this.role, other.role) && _dafny.areEqual(this.key, other.key) && this.algKnown === other.algKnown && this.pqPkOk === other.pqPkOk && _dafny.areEqual(this.sigOk, other.sigOk);
      } else  {
        return false; // unexpected
      }
    }
    static Default(_default_K) {
      return Threshold.Share.create_Share(false, Common.Option.Default(), _default_K, false, false, function () { return false; });
    }
    static Rtd(rtd$_K) {
      return class {
        static get Default() {
          return Share.Default(rtd$_K.Default);
        }
      };
    }
  }

  $module.Baseline = class Baseline {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Baseline(holderIsString, holder, pqKeyOk, leafSigOk) {
      let $dt = new Baseline(0);
      $dt.holderIsString = holderIsString;
      $dt.holder = holder;
      $dt.pqKeyOk = pqKeyOk;
      $dt.leafSigOk = leafSigOk;
      return $dt;
    }
    get is_Baseline() { return this.$tag === 0; }
    get dtor_holderIsString() { return this.holderIsString; }
    get dtor_holder() { return this.holder; }
    get dtor_pqKeyOk() { return this.pqKeyOk; }
    get dtor_leafSigOk() { return this.leafSigOk; }
    toString() {
      if (this.$tag === 0) {
        return "Threshold.Baseline.Baseline" + "(" + _dafny.toString(this.holderIsString) + ", " + _dafny.toString(this.holder) + ", " + _dafny.toString(this.pqKeyOk) + ", " + _dafny.toString(this.leafSigOk) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.holderIsString === other.holderIsString && _dafny.areEqual(this.holder, other.holder) && _dafny.areEqual(this.pqKeyOk, other.pqKeyOk) && _dafny.areEqual(this.leafSigOk, other.leafSigOk);
      } else  {
        return false; // unexpected
      }
    }
    static Default(_default_K) {
      return Threshold.Baseline.create_Baseline(false, _default_K, function () { return false; }, function () { return false; });
    }
    static Rtd(rtd$_K) {
      return class {
        static get Default() {
          return Baseline.Default(rtd$_K.Default);
        }
      };
    }
  }

  $module.ThReason = class ThReason {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_InvalidT() {
      let $dt = new ThReason(0);
      return $dt;
    }
    static create_SetMalformed() {
      let $dt = new ThReason(1);
      return $dt;
    }
    static create_SetPq() {
      let $dt = new ThReason(2);
      return $dt;
    }
    static create_TwoKeysForRole(entry) {
      let $dt = new ThReason(3);
      $dt.entry = entry;
      return $dt;
    }
    static create_OneKeyTwoRoles() {
      let $dt = new ThReason(4);
      return $dt;
    }
    static create_MalformedShare() {
      let $dt = new ThReason(5);
      return $dt;
    }
    static create_RoleNotInSet(share) {
      let $dt = new ThReason(6);
      $dt.share = share;
      return $dt;
    }
    static create_KeyNotRegistered(share) {
      let $dt = new ThReason(7);
      $dt.share = share;
      return $dt;
    }
    static create_UnknownAlg(share) {
      let $dt = new ThReason(8);
      $dt.share = share;
      return $dt;
    }
    static create_PqPkMismatch(share) {
      let $dt = new ThReason(9);
      $dt.share = share;
      return $dt;
    }
    static create_InvalidSig(share) {
      let $dt = new ThReason(10);
      $dt.share = share;
      return $dt;
    }
    static create_NeedMore() {
      let $dt = new ThReason(11);
      return $dt;
    }
    get is_InvalidT() { return this.$tag === 0; }
    get is_SetMalformed() { return this.$tag === 1; }
    get is_SetPq() { return this.$tag === 2; }
    get is_TwoKeysForRole() { return this.$tag === 3; }
    get is_OneKeyTwoRoles() { return this.$tag === 4; }
    get is_MalformedShare() { return this.$tag === 5; }
    get is_RoleNotInSet() { return this.$tag === 6; }
    get is_KeyNotRegistered() { return this.$tag === 7; }
    get is_UnknownAlg() { return this.$tag === 8; }
    get is_PqPkMismatch() { return this.$tag === 9; }
    get is_InvalidSig() { return this.$tag === 10; }
    get is_NeedMore() { return this.$tag === 11; }
    get dtor_entry() { return this.entry; }
    get dtor_share() { return this.share; }
    toString() {
      if (this.$tag === 0) {
        return "Threshold.ThReason.InvalidT";
      } else if (this.$tag === 1) {
        return "Threshold.ThReason.SetMalformed";
      } else if (this.$tag === 2) {
        return "Threshold.ThReason.SetPq";
      } else if (this.$tag === 3) {
        return "Threshold.ThReason.TwoKeysForRole" + "(" + _dafny.toString(this.entry) + ")";
      } else if (this.$tag === 4) {
        return "Threshold.ThReason.OneKeyTwoRoles";
      } else if (this.$tag === 5) {
        return "Threshold.ThReason.MalformedShare";
      } else if (this.$tag === 6) {
        return "Threshold.ThReason.RoleNotInSet" + "(" + _dafny.toString(this.share) + ")";
      } else if (this.$tag === 7) {
        return "Threshold.ThReason.KeyNotRegistered" + "(" + _dafny.toString(this.share) + ")";
      } else if (this.$tag === 8) {
        return "Threshold.ThReason.UnknownAlg" + "(" + _dafny.toString(this.share) + ")";
      } else if (this.$tag === 9) {
        return "Threshold.ThReason.PqPkMismatch" + "(" + _dafny.toString(this.share) + ")";
      } else if (this.$tag === 10) {
        return "Threshold.ThReason.InvalidSig" + "(" + _dafny.toString(this.share) + ")";
      } else if (this.$tag === 11) {
        return "Threshold.ThReason.NeedMore";
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
        return other.$tag === 3 && _dafny.areEqual(this.entry, other.entry);
      } else if (this.$tag === 4) {
        return other.$tag === 4;
      } else if (this.$tag === 5) {
        return other.$tag === 5;
      } else if (this.$tag === 6) {
        return other.$tag === 6 && _dafny.areEqual(this.share, other.share);
      } else if (this.$tag === 7) {
        return other.$tag === 7 && _dafny.areEqual(this.share, other.share);
      } else if (this.$tag === 8) {
        return other.$tag === 8 && _dafny.areEqual(this.share, other.share);
      } else if (this.$tag === 9) {
        return other.$tag === 9 && _dafny.areEqual(this.share, other.share);
      } else if (this.$tag === 10) {
        return other.$tag === 10 && _dafny.areEqual(this.share, other.share);
      } else if (this.$tag === 11) {
        return other.$tag === 11;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Threshold.ThReason.create_InvalidT();
    }
    static Rtd() {
      return class {
        static get Default() {
          return ThReason.Default();
        }
      };
    }
  }

  $module.ThVerdict = class ThVerdict {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_ThVerdict(ok, count, roles, reason) {
      let $dt = new ThVerdict(0);
      $dt.ok = ok;
      $dt.count = count;
      $dt.roles = roles;
      $dt.reason = reason;
      return $dt;
    }
    get is_ThVerdict() { return this.$tag === 0; }
    get dtor_ok() { return this.ok; }
    get dtor_count() { return this.count; }
    get dtor_roles() { return this.roles; }
    get dtor_reason() { return this.reason; }
    toString() {
      if (this.$tag === 0) {
        return "Threshold.ThVerdict.ThVerdict" + "(" + _dafny.toString(this.ok) + ", " + _dafny.toString(this.count) + ", " + _dafny.toString(this.roles) + ", " + _dafny.toString(this.reason) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.ok === other.ok && _dafny.areEqual(this.count, other.count) && _dafny.areEqual(this.roles, other.roles) && _dafny.areEqual(this.reason, other.reason);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Threshold.ThVerdict.create_ThVerdict(false, _dafny.ZERO, _dafny.Seq.of(), Common.Option.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return ThVerdict.Default();
        }
      };
    }
  }

  $module.RegResult = class RegResult {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_RegOk(reg) {
      let $dt = new RegResult(0);
      $dt.reg = reg;
      return $dt;
    }
    static create_RegBad(r) {
      let $dt = new RegResult(1);
      $dt.r = r;
      return $dt;
    }
    get is_RegOk() { return this.$tag === 0; }
    get is_RegBad() { return this.$tag === 1; }
    get dtor_reg() { return this.reg; }
    get dtor_r() { return this.r; }
    toString() {
      if (this.$tag === 0) {
        return "Threshold.RegResult.RegOk" + "(" + _dafny.toString(this.reg) + ")";
      } else if (this.$tag === 1) {
        return "Threshold.RegResult.RegBad" + "(" + _dafny.toString(this.r) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.reg, other.reg);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.r, other.r);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Threshold.RegResult.create_RegOk(_dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return RegResult.Default();
        }
      };
    }
  }

  $module.St = class St {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_St(keys, roles, reason) {
      let $dt = new St(0);
      $dt.keys = keys;
      $dt.roles = roles;
      $dt.reason = reason;
      return $dt;
    }
    get is_St() { return this.$tag === 0; }
    get dtor_keys() { return this.keys; }
    get dtor_roles() { return this.roles; }
    get dtor_reason() { return this.reason; }
    toString() {
      if (this.$tag === 0) {
        return "Threshold.St.St" + "(" + _dafny.toString(this.keys) + ", " + _dafny.toString(this.roles) + ", " + _dafny.toString(this.reason) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.keys, other.keys) && _dafny.areEqual(this.roles, other.roles) && _dafny.areEqual(this.reason, other.reason);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Threshold.St.create_St(_dafny.Seq.of(), _dafny.Seq.of(), Common.Option.Default());
    }
    static Rtd() {
      return class {
        static get Default() {
          return St.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module Threshold
let Replay = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Replay._default";
    }
    _parentTraits() {
      return [];
    }
    static WindowOk(f) {
      return ((((f).dtor_iatOk) && ((f).dtor_expOk)) && (((f).dtor_iat).isLessThan((f).dtor_exp))) && ((((f).dtor_exp).minus((f).dtor_iat)).isLessThanOrEqualTo(Replay.__default.MaxLifetimeMs));
    };
    static Pre(f) {
      if (!((f).dtor_nowOk)) {
        return Common.Option.create_Some(Replay.Deny.create_Malformed());
      } else if (!((f).dtor_verifierAudOk)) {
        return Common.Option.create_Some(Replay.Deny.create_Malformed());
      } else if (!((f).dtor_isObject)) {
        return Common.Option.create_Some(Replay.Deny.create_Malformed());
      } else if (!((f).dtor_audMatches)) {
        return Common.Option.create_Some(Replay.Deny.create_Audience());
      } else if (!(Replay.__default.WindowOk(f))) {
        return Common.Option.create_Some(Replay.Deny.create_Malformed());
      } else if ((((f).dtor_now).plus((f).dtor_skew)).isLessThan((f).dtor_iat)) {
        return Common.Option.create_Some(Replay.Deny.create_NotYetValid());
      } else if (((f).dtor_exp).isLessThan((f).dtor_now)) {
        return Common.Option.create_Some(Replay.Deny.create_Expired());
      } else if (!((f).dtor_leafOk)) {
        return Common.Option.create_Some(Replay.Deny.create_Malformed());
      } else if (!((f).dtor_componentsOk)) {
        return Common.Option.create_Some(Replay.Deny.create_Malformed());
      } else if (!((f).dtor_counterOk)) {
        return Common.Option.create_Some(Replay.Deny.create_Malformed());
      } else {
        return Common.Option.create_None();
      }
    };
    static NonceStage(f) {
      if ((f).dtor_hasNonce) {
        if ((f).dtor_nonceOk) {
          return Replay.NonceAct.create_ConsumeNonce();
        } else {
          return Replay.NonceAct.create_DenyNonce();
        }
      } else if ((f).dtor_requireNonce) {
        return Replay.NonceAct.create_DenyNonce();
      } else {
        return Replay.NonceAct.create_SkipNonce();
      }
    };
    static RetainUntil(f) {
      return ((f).dtor_exp).plus((f).dtor_skew);
    };
    static Decide(f, consumedFirst, advanced) {
      let _source0 = Replay.__default.Pre(f);
      {
        if (_source0.is_Some) {
          let _0_d = (_source0).v;
          return Common.Option.create_Some(_0_d);
        }
      }
      {
        let _source1 = Replay.__default.NonceStage(f);
        {
          if (_source1.is_DenyNonce) {
            return Common.Option.create_Some(Replay.Deny.create_Malformed());
          }
        }
        {
          if (_source1.is_ConsumeNonce) {
            if (!(consumedFirst)) {
              return Common.Option.create_Some(Replay.Deny.create_Replay());
            } else if (((f).dtor_hasCounters) && (!(advanced))) {
              return Common.Option.create_Some(Replay.Deny.create_Replay());
            } else {
              return Common.Option.create_None();
            }
          }
        }
        {
          if (((f).dtor_hasCounters) && (!(advanced))) {
            return Common.Option.create_Some(Replay.Deny.create_Replay());
          } else {
            return Common.Option.create_None();
          }
        }
      }
    };
    static PruneMap(m, now) {
      return function () {
        let _coll0 = new _dafny.Map();
        for (const _compr_0 of (m).Keys.Elements) {
          let _0_k = _compr_0;
          if (((m).contains(_0_k)) && ((now).isLessThanOrEqualTo((m).get(_0_k)))) {
            _coll0.push([_0_k,(m).get(_0_k)]);
          }
        }
        return _coll0;
      }();
    };
    static ConsumeOnce(s, key, retain, now) {
      if (((new BigNumber((key).length)).isEqualTo(_dafny.ZERO)) || ((retain).isLessThan(now))) {
        return _dafny.Tuple.of(s, Replay.Out.create_Rejected());
      } else if ((((s).dtor_seen).contains(key)) && ((now).isLessThanOrEqualTo(((s).dtor_seen).get(key)))) {
        return _dafny.Tuple.of(s, Replay.Out.create_Dup());
      } else {
        let _0_s1 = (((!((s).dtor_seen).contains(key)) && (((s).dtor_maxEntries).isLessThanOrEqualTo(new BigNumber(((s).dtor_seen).length)))) ? (Replay.Store.create_Store(Replay.__default.PruneMap((s).dtor_seen, now), (s).dtor_streams, (s).dtor_maxEntries)) : (s));
        if ((!((_0_s1).dtor_seen).contains(key)) && (((_0_s1).dtor_maxEntries).isLessThanOrEqualTo(new BigNumber(((_0_s1).dtor_seen).length)))) {
          return _dafny.Tuple.of(_0_s1, Replay.Out.create_Rejected());
        } else {
          let _1_until = ((((_0_s1).dtor_seen).contains(key)) ? (((_0_s1).dtor_seen).get(key)) : (_dafny.ZERO));
          return _dafny.Tuple.of(Replay.Store.create_Store(((_0_s1).dtor_seen).update(key, (((_1_until).isLessThanOrEqualTo(retain)) ? (retain) : (_1_until))), (_0_s1).dtor_streams, (_0_s1).dtor_maxEntries), Replay.Out.create_Accepted());
        }
      }
    };
    static AdvanceCounter(s, stream, c) {
      if (((new BigNumber((stream).length)).isEqualTo(_dafny.ZERO)) || ((c).isLessThan(_dafny.ZERO))) {
        return _dafny.Tuple.of(s, Replay.Out.create_Rejected());
      } else if ((((s).dtor_streams).contains(stream)) && (!((((s).dtor_streams).get(stream)).isLessThan(c)))) {
        return _dafny.Tuple.of(s, Replay.Out.create_Dup());
      } else {
        return _dafny.Tuple.of(Replay.Store.create_Store((s).dtor_seen, ((s).dtor_streams).update(stream, c), (s).dtor_maxEntries), Replay.Out.create_Accepted());
      }
    };
    static Apply(s, op) {
      let _source0 = op;
      {
        if (_source0.is_Consume) {
          let _0_k = (_source0).key;
          let _1_r = (_source0).retain;
          let _2_n = (_source0).now;
          return Replay.__default.ConsumeOnce(s, _0_k, _1_r, _2_n);
        }
      }
      {
        if (_source0.is_Prune) {
          let _3_n = (_source0).now;
          return _dafny.Tuple.of(Replay.Store.create_Store(Replay.__default.PruneMap((s).dtor_seen, _3_n), (s).dtor_streams, (s).dtor_maxEntries), Replay.Out.create_Accepted());
        }
      }
      {
        let _4_st = (_source0).stream;
        let _5_c = (_source0).counter;
        return Replay.__default.AdvanceCounter(s, _4_st, _5_c);
      }
    };
    static Run(s, ops) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((ops).length)).isEqualTo(_dafny.ZERO)) {
          return s;
        } else {
          let _in0 = (Replay.__default.Apply(s, (ops)[_dafny.ZERO]))[0];
          let _in1 = (ops).slice(_dafny.ONE);
          s = _in0;
          ops = _in1;
          continue TAIL_CALL_START;
        }
      }
    };
    static OpTime(op) {
      let _source0 = op;
      {
        if (_source0.is_Consume) {
          let _0_n = (_source0).now;
          return Common.Option.create_Some(_0_n);
        }
      }
      {
        if (_source0.is_Prune) {
          let _1_n = (_source0).now;
          return Common.Option.create_Some(_1_n);
        }
      }
      {
        return Common.Option.create_None();
      }
    };
    static get MaxLifetimeMs() {
      return new BigNumber(3600000);
    };
    static get MaxSkewMs() {
      return new BigNumber(60000);
    };
  };

  $module.Deny = class Deny {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Malformed() {
      let $dt = new Deny(0);
      return $dt;
    }
    static create_Audience() {
      let $dt = new Deny(1);
      return $dt;
    }
    static create_NotYetValid() {
      let $dt = new Deny(2);
      return $dt;
    }
    static create_Expired() {
      let $dt = new Deny(3);
      return $dt;
    }
    static create_Replay() {
      let $dt = new Deny(4);
      return $dt;
    }
    static create_StoreUnavailable() {
      let $dt = new Deny(5);
      return $dt;
    }
    get is_Malformed() { return this.$tag === 0; }
    get is_Audience() { return this.$tag === 1; }
    get is_NotYetValid() { return this.$tag === 2; }
    get is_Expired() { return this.$tag === 3; }
    get is_Replay() { return this.$tag === 4; }
    get is_StoreUnavailable() { return this.$tag === 5; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield Deny.create_Malformed();
      yield Deny.create_Audience();
      yield Deny.create_NotYetValid();
      yield Deny.create_Expired();
      yield Deny.create_Replay();
      yield Deny.create_StoreUnavailable();
    }
    toString() {
      if (this.$tag === 0) {
        return "Replay.Deny.Malformed";
      } else if (this.$tag === 1) {
        return "Replay.Deny.Audience";
      } else if (this.$tag === 2) {
        return "Replay.Deny.NotYetValid";
      } else if (this.$tag === 3) {
        return "Replay.Deny.Expired";
      } else if (this.$tag === 4) {
        return "Replay.Deny.Replay";
      } else if (this.$tag === 5) {
        return "Replay.Deny.StoreUnavailable";
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
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Replay.Deny.create_Malformed();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Deny.Default();
        }
      };
    }
  }

  $module.Facts = class Facts {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Facts(nowOk, verifierAudOk, isObject, audMatches, iatOk, expOk, iat, exp, now, skew, leafOk, componentsOk, counterOk, hasNonce, nonceOk, requireNonce, hasCounters) {
      let $dt = new Facts(0);
      $dt.nowOk = nowOk;
      $dt.verifierAudOk = verifierAudOk;
      $dt.isObject = isObject;
      $dt.audMatches = audMatches;
      $dt.iatOk = iatOk;
      $dt.expOk = expOk;
      $dt.iat = iat;
      $dt.exp = exp;
      $dt.now = now;
      $dt.skew = skew;
      $dt.leafOk = leafOk;
      $dt.componentsOk = componentsOk;
      $dt.counterOk = counterOk;
      $dt.hasNonce = hasNonce;
      $dt.nonceOk = nonceOk;
      $dt.requireNonce = requireNonce;
      $dt.hasCounters = hasCounters;
      return $dt;
    }
    get is_Facts() { return this.$tag === 0; }
    get dtor_nowOk() { return this.nowOk; }
    get dtor_verifierAudOk() { return this.verifierAudOk; }
    get dtor_isObject() { return this.isObject; }
    get dtor_audMatches() { return this.audMatches; }
    get dtor_iatOk() { return this.iatOk; }
    get dtor_expOk() { return this.expOk; }
    get dtor_iat() { return this.iat; }
    get dtor_exp() { return this.exp; }
    get dtor_now() { return this.now; }
    get dtor_skew() { return this.skew; }
    get dtor_leafOk() { return this.leafOk; }
    get dtor_componentsOk() { return this.componentsOk; }
    get dtor_counterOk() { return this.counterOk; }
    get dtor_hasNonce() { return this.hasNonce; }
    get dtor_nonceOk() { return this.nonceOk; }
    get dtor_requireNonce() { return this.requireNonce; }
    get dtor_hasCounters() { return this.hasCounters; }
    toString() {
      if (this.$tag === 0) {
        return "Replay.Facts.Facts" + "(" + _dafny.toString(this.nowOk) + ", " + _dafny.toString(this.verifierAudOk) + ", " + _dafny.toString(this.isObject) + ", " + _dafny.toString(this.audMatches) + ", " + _dafny.toString(this.iatOk) + ", " + _dafny.toString(this.expOk) + ", " + _dafny.toString(this.iat) + ", " + _dafny.toString(this.exp) + ", " + _dafny.toString(this.now) + ", " + _dafny.toString(this.skew) + ", " + _dafny.toString(this.leafOk) + ", " + _dafny.toString(this.componentsOk) + ", " + _dafny.toString(this.counterOk) + ", " + _dafny.toString(this.hasNonce) + ", " + _dafny.toString(this.nonceOk) + ", " + _dafny.toString(this.requireNonce) + ", " + _dafny.toString(this.hasCounters) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && this.nowOk === other.nowOk && this.verifierAudOk === other.verifierAudOk && this.isObject === other.isObject && this.audMatches === other.audMatches && this.iatOk === other.iatOk && this.expOk === other.expOk && _dafny.areEqual(this.iat, other.iat) && _dafny.areEqual(this.exp, other.exp) && _dafny.areEqual(this.now, other.now) && _dafny.areEqual(this.skew, other.skew) && this.leafOk === other.leafOk && this.componentsOk === other.componentsOk && this.counterOk === other.counterOk && this.hasNonce === other.hasNonce && this.nonceOk === other.nonceOk && this.requireNonce === other.requireNonce && this.hasCounters === other.hasCounters;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Replay.Facts.create_Facts(false, false, false, false, false, false, _dafny.ZERO, _dafny.ZERO, _dafny.ZERO, _dafny.ZERO, false, false, false, false, false, false, false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Facts.Default();
        }
      };
    }
  }

  $module.NonceAct = class NonceAct {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_SkipNonce() {
      let $dt = new NonceAct(0);
      return $dt;
    }
    static create_ConsumeNonce() {
      let $dt = new NonceAct(1);
      return $dt;
    }
    static create_DenyNonce() {
      let $dt = new NonceAct(2);
      return $dt;
    }
    get is_SkipNonce() { return this.$tag === 0; }
    get is_ConsumeNonce() { return this.$tag === 1; }
    get is_DenyNonce() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield NonceAct.create_SkipNonce();
      yield NonceAct.create_ConsumeNonce();
      yield NonceAct.create_DenyNonce();
    }
    toString() {
      if (this.$tag === 0) {
        return "Replay.NonceAct.SkipNonce";
      } else if (this.$tag === 1) {
        return "Replay.NonceAct.ConsumeNonce";
      } else if (this.$tag === 2) {
        return "Replay.NonceAct.DenyNonce";
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
      return Replay.NonceAct.create_SkipNonce();
    }
    static Rtd() {
      return class {
        static get Default() {
          return NonceAct.Default();
        }
      };
    }
  }

  $module.Store = class Store {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Store(seen, streams, maxEntries) {
      let $dt = new Store(0);
      $dt.seen = seen;
      $dt.streams = streams;
      $dt.maxEntries = maxEntries;
      return $dt;
    }
    get is_Store() { return this.$tag === 0; }
    get dtor_seen() { return this.seen; }
    get dtor_streams() { return this.streams; }
    get dtor_maxEntries() { return this.maxEntries; }
    toString() {
      if (this.$tag === 0) {
        return "Replay.Store.Store" + "(" + _dafny.toString(this.seen) + ", " + _dafny.toString(this.streams) + ", " + _dafny.toString(this.maxEntries) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.seen, other.seen) && _dafny.areEqual(this.streams, other.streams) && _dafny.areEqual(this.maxEntries, other.maxEntries);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Replay.Store.create_Store(_dafny.Map.Empty, _dafny.Map.Empty, _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Store.Default();
        }
      };
    }
  }

  $module.Op = class Op {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Consume(key, retain, now) {
      let $dt = new Op(0);
      $dt.key = key;
      $dt.retain = retain;
      $dt.now = now;
      return $dt;
    }
    static create_Prune(now) {
      let $dt = new Op(1);
      $dt.now = now;
      return $dt;
    }
    static create_Advance(stream, counter) {
      let $dt = new Op(2);
      $dt.stream = stream;
      $dt.counter = counter;
      return $dt;
    }
    get is_Consume() { return this.$tag === 0; }
    get is_Prune() { return this.$tag === 1; }
    get is_Advance() { return this.$tag === 2; }
    get dtor_key() { return this.key; }
    get dtor_retain() { return this.retain; }
    get dtor_now() { return this.now; }
    get dtor_stream() { return this.stream; }
    get dtor_counter() { return this.counter; }
    toString() {
      if (this.$tag === 0) {
        return "Replay.Op.Consume" + "(" + this.key.toVerbatimString(true) + ", " + _dafny.toString(this.retain) + ", " + _dafny.toString(this.now) + ")";
      } else if (this.$tag === 1) {
        return "Replay.Op.Prune" + "(" + _dafny.toString(this.now) + ")";
      } else if (this.$tag === 2) {
        return "Replay.Op.Advance" + "(" + this.stream.toVerbatimString(true) + ", " + _dafny.toString(this.counter) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.key, other.key) && _dafny.areEqual(this.retain, other.retain) && _dafny.areEqual(this.now, other.now);
      } else if (this.$tag === 1) {
        return other.$tag === 1 && _dafny.areEqual(this.now, other.now);
      } else if (this.$tag === 2) {
        return other.$tag === 2 && _dafny.areEqual(this.stream, other.stream) && _dafny.areEqual(this.counter, other.counter);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Replay.Op.create_Consume(_dafny.Seq.UnicodeFromString(""), _dafny.ZERO, _dafny.ZERO);
    }
    static Rtd() {
      return class {
        static get Default() {
          return Op.Default();
        }
      };
    }
  }

  $module.Out = class Out {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_Accepted() {
      let $dt = new Out(0);
      return $dt;
    }
    static create_Dup() {
      let $dt = new Out(1);
      return $dt;
    }
    static create_Rejected() {
      let $dt = new Out(2);
      return $dt;
    }
    get is_Accepted() { return this.$tag === 0; }
    get is_Dup() { return this.$tag === 1; }
    get is_Rejected() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield Out.create_Accepted();
      yield Out.create_Dup();
      yield Out.create_Rejected();
    }
    toString() {
      if (this.$tag === 0) {
        return "Replay.Out.Accepted";
      } else if (this.$tag === 1) {
        return "Replay.Out.Dup";
      } else if (this.$tag === 2) {
        return "Replay.Out.Rejected";
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
      return Replay.Out.create_Accepted();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Out.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module Replay
let Verdict = (function() {
  let $module = {};

  $module.__default = class __default {
    constructor () {
      this._tname = "Verdict._default";
    }
    _parentTraits() {
      return [];
    }
    static AudienceStatus(hasAud, arg, equal) {
      let _source0 = arg;
      {
        if (_source0.is_AudNull) {
          return Common.Status.create_NotEnforced();
        }
      }
      {
        if (_source0.is_AudAbsent) {
          if (hasAud) {
            return Common.Status.create_Fail();
          } else {
            return Common.Status.create_NotEnforced();
          }
        }
      }
      {
        if (equal) {
          return Common.Status.create_Pass();
        } else {
          return Common.Status.create_Fail();
        }
      }
    };
    static ValidityDecision(clockOk, iat, exp, now) {
      if (!(clockOk)) {
        return Verdict.Validity.create_VBadClock();
      } else if (!((iat).isLessThan(exp))) {
        return Verdict.Validity.create_VNotGreater();
      } else if ((Verdict.__default.MaxLifetimeMs).isLessThan((exp).minus(iat))) {
        return Verdict.Validity.create_VTooLong();
      } else if (((now).plus(Verdict.__default.MaxSkewMs)).isLessThan(iat)) {
        return Verdict.Validity.create_VFuture();
      } else if ((exp).isLessThan(now)) {
        return Verdict.Validity.create_VExpired();
      } else {
        return Verdict.Validity.create_VPass();
      }
    };
    static VersionStatus(versionOk) {
      if (versionOk) {
        return Common.Status.create_Pass();
      } else {
        return Common.Status.create_Fail();
      }
    };
    static GrantRefBoundStatus(grantRefNonEmptyString, rootIdIsString, equal) {
      if (((grantRefNonEmptyString) && (rootIdIsString)) && (equal)) {
        return Common.Status.create_Pass();
      } else {
        return Common.Status.create_Fail();
      }
    };
    static CounterStatus(nonNegSafeInt) {
      if (nonNegSafeInt) {
        return Common.Status.create_Pass();
      } else {
        return Common.Status.create_Fail();
      }
    };
    static SuitePolicy(policyDefined, algAllowed) {
      if ((policyDefined) && (!(algAllowed))) {
        return Common.Option.create_Some(Verdict.SuiteViolation.create_NotAllowed());
      } else {
        return Common.Option.create_None();
      }
    };
    static PqBinding(needsPqKey, allowUnbound, committed, matches) {
      if ((!(needsPqKey)) || (allowUnbound)) {
        return Common.Option.create_None();
      } else if (!(committed)) {
        return Common.Option.create_Some(Verdict.SuiteViolation.create_NoPqCommitment());
      } else if (!(matches)) {
        return Common.Option.create_Some(Verdict.SuiteViolation.create_PqMismatch());
      } else {
        return Common.Option.create_None();
      }
    };
    static PqResolve(trusted, artifactKeyOk, pinPresent, pinEquals, commitPresent, commitMatches, allowUnbound) {
      if (trusted) {
        return Verdict.PqResolution.create_PqTrusted();
      } else if (!(artifactKeyOk)) {
        return Verdict.PqResolution.create_PqRefused();
      } else if (pinPresent) {
        if (pinEquals) {
          return Verdict.PqResolution.create_PqPinned();
        } else {
          return Verdict.PqResolution.create_PqRefused();
        }
      } else if ((commitPresent) && (commitMatches)) {
        return Verdict.PqResolution.create_PqCommitted();
      } else if (allowUnbound) {
        return Verdict.PqResolution.create_PqUnbound();
      } else {
        return Verdict.PqResolution.create_PqRefused();
      }
    };
    static LeafDecision(leafPresent, suiteErr, sigIsString, verify) {
      if (!(leafPresent)) {
        return Verdict.LeafOut.create_LeafBadSig();
      } else {
        let _source0 = (suiteErr)();
        {
          if (_source0.is_Err) {
            let _0_m = (_source0).m;
            return Verdict.LeafOut.create_LeafSuiteErr(_0_m);
          }
        }
        {
          if ((sigIsString) && ((verify)())) {
            return Verdict.LeafOut.create_LeafPass();
          } else {
            return Verdict.LeafOut.create_LeafBadSig();
          }
        }
      }
    };
    static CapChainStatus(nonEmpty, rootIsGrant, walk) {
      if (!(nonEmpty)) {
        return Verdict.CapChainOut.create_CapEmpty();
      } else if (!((rootIsGrant)())) {
        return Verdict.CapChainOut.create_CapRootNotGrant();
      } else {
        return Verdict.CapChainOut.create_CapWalked((walk)());
      }
    };
    static HookStatus(enforced, ok) {
      if (!(enforced)) {
        return Common.Status.create_NotEnforced();
      } else if (ok) {
        return Common.Status.create_Pass();
      } else {
        return Common.Status.create_Fail();
      }
    };
    static CoreInit() {
      return Verdict.CoreSt.create_CoreSt(_dafny.Seq.of(), Common.Option.create_None(), false);
    };
    static CoreFail(st, name, why) {
      return Verdict.CoreSt.create_CoreSt(Common.__default.Set((st).dtor_checks, name, Common.Status.create_Fail()), ((((st).dtor_reason).is_Some) ? ((st).dtor_reason) : (Common.Option.create_Some((why)()))), (st).dtor_terminal);
    };
    static CoreSet(st, name, s) {
      return Verdict.CoreSt.create_CoreSt(Common.__default.Set((st).dtor_checks, name, s), (st).dtor_reason, (st).dtor_terminal);
    };
    static CoreWireFail(wire, why) {
      return Verdict.CoreSt.create_CoreSt(_dafny.Seq.of(_dafny.Tuple.of(wire, Common.Status.create_Fail())), Common.Option.create_Some(why), true);
    };
    static CoreMalformed(st, malformed, why) {
      return Verdict.CoreSt.create_CoreSt(Common.__default.Set((st).dtor_checks, malformed, Common.Status.create_Fail()), ((((st).dtor_reason).is_Some) ? ((st).dtor_reason) : (Common.Option.create_Some(why))), (st).dtor_terminal);
    };
    static CoreAllow(st) {
      return (!((st).dtor_terminal)) && (!(Common.__default.HasFail((st).dtor_checks)));
    };
    static CoreReason(st) {
      if (Verdict.__default.CoreAllow(st)) {
        return Common.Option.create_None();
      } else {
        return (st).dtor_reason;
      }
    };
    static ZkRule(st, zk, why) {
      let _0_c = Common.__default.Get((st).dtor_checks, zk);
      if ((_dafny.areEqual(_0_c, Common.Option.create_Some(Common.Status.create_Pass()))) || (_dafny.areEqual(_0_c, Common.Option.create_Some(Common.Status.create_Fail())))) {
        return st;
      } else {
        return Verdict.__default.CoreFail(st, zk, why);
      }
    };
    static AttestGate(st, att, gateOn, required, why) {
      if (((gateOn) && (required)) && (_dafny.areEqual(Common.__default.Get((st).dtor_checks, att), Common.Option.create_Some(Common.Status.create_NotEnforced())))) {
        return Verdict.__default.CoreFail(st, att, why);
      } else {
        return st;
      }
    };
    static VFail(st, name, why) {
      return Verdict.VSt.create_VSt(Common.__default.Set((st).dtor_checks, name, Common.Status.create_Fail()), _dafny.Seq.Concat((st).dtor_reasons, _dafny.Seq.of((why)())));
    };
    static VSet(st, name, s) {
      return Verdict.VSt.create_VSt(Common.__default.Set((st).dtor_checks, name, s), (st).dtor_reasons);
    };
    static VPush(st, m) {
      return Verdict.VSt.create_VSt((st).dtor_checks, _dafny.Seq.Concat((st).dtor_reasons, _dafny.Seq.of(m)));
    };
    static VPushAll(st, ms) {
      return Verdict.VSt.create_VSt((st).dtor_checks, _dafny.Seq.Concat((st).dtor_reasons, ms));
    };
    static PlanDecision(planSupplied, rootMatches, authorized) {
      if (!(planSupplied)) {
        return Verdict.PlanOut.create_PlanNotEnforced();
      } else if (!(rootMatches)) {
        return Verdict.PlanOut.create_PlanMismatch();
      } else {
        let _source0 = authorized;
        {
          if (_source0.is_Some) {
            let v0 = (_source0).v;
            if ((v0) === (true)) {
              return Verdict.PlanOut.create_PlanPass();
            }
          }
        }
        {
          if (_source0.is_Some) {
            let v1 = (_source0).v;
            if ((v1) === (false)) {
              return Verdict.PlanOut.create_PlanUnauthorized();
            }
          }
        }
        {
          return Verdict.PlanOut.create_PlanNotEnforced();
        }
      }
    };
    static BeaconDecision(supplied, verifierOk, replayed, refBinds) {
      if (!(supplied)) {
        return Verdict.BeaconOut.create_BeaconNotEnforced();
      } else if (!(verifierOk)) {
        return Verdict.BeaconOut.create_BeaconRejected();
      } else if (replayed) {
        return Verdict.BeaconOut.create_BeaconReplayed();
      } else if (!(refBinds)) {
        return Verdict.BeaconOut.create_BeaconUnbound();
      } else {
        return Verdict.BeaconOut.create_BeaconPass();
      }
    };
    static AttestationRequiredFails(requiresAtt, checks, att) {
      return (requiresAtt) && (!_dafny.areEqual(Common.__default.Get(checks, att), Common.Option.create_Some(Common.Status.create_Pass())));
    };
    static RevDecision(declaredRank, serverRank) {
      let _source0 = serverRank;
      {
        if (_source0.is_None) {
          return Verdict.RevOut.create_RevNoServerClass();
        }
      }
      {
        let _0_sr = (_source0).v;
        if ((declaredRank).isLessThan(_0_sr)) {
          return Verdict.RevOut.create_RevLessRestrictive();
        } else {
          return Verdict.RevOut.create_RevPass();
        }
      }
    };
    static UseDeclared(declaredRank, serverRank) {
      let _source0 = serverRank;
      {
        if (_source0.is_None) {
          return true;
        }
      }
      {
        let _0_sr = (_source0).v;
        return (_0_sr).isLessThan(declaredRank);
      }
    };
    static ThresholdRule(tReq, release, th, hookT) {
      if (((((_dafny.ONE).isLessThan(tReq)) && (release)) && (_dafny.areEqual(th, Common.Option.create_Some(Common.Status.create_Pass())))) && (!(((hookT).is_Some) && ((tReq).isLessThanOrEqualTo((hookT).dtor_v))))) {
        return Verdict.ThrOut.create_ThrBelow();
      } else if ((((_dafny.ONE).isLessThan(tReq)) && (release)) && (!_dafny.areEqual(th, Common.Option.create_Some(Common.Status.create_Pass())))) {
        if (_dafny.areEqual(th, Common.Option.create_Some(Common.Status.create_Fail()))) {
          return Verdict.ThrOut.create_ThrRejected();
        } else {
          return Verdict.ThrOut.create_ThrNoVerifier();
        }
      } else {
        return Verdict.ThrOut.create_ThrOk();
      }
    };
    static FinalAllow(checks, release, coreAllow) {
      return ((!(Common.__default.HasFail(checks))) && (release)) && (coreAllow);
    };
    static Enforce(allow, checks, reasons, req, mk) {
      TAIL_CALL_START: while (true) {
        if ((new BigNumber((req).length)).isEqualTo(_dafny.ZERO)) {
          return _dafny.Tuple.of(allow, checks, reasons);
        } else {
          let _0_c = Common.__default.Get(checks, (req)[_dafny.ZERO]);
          if (_dafny.areEqual(_0_c, Common.Option.create_Some(Common.Status.create_Pass()))) {
            let _in0 = allow;
            let _in1 = checks;
            let _in2 = reasons;
            let _in3 = (req).slice(_dafny.ONE);
            let _in4 = mk;
            allow = _in0;
            checks = _in1;
            reasons = _in2;
            req = _in3;
            mk = _in4;
            continue TAIL_CALL_START;
          } else if (_dafny.areEqual(_0_c, Common.Option.create_Some(Common.Status.create_Fail()))) {
            let _in5 = false;
            let _in6 = checks;
            let _in7 = reasons;
            let _in8 = (req).slice(_dafny.ONE);
            let _in9 = mk;
            allow = _in5;
            checks = _in6;
            reasons = _in7;
            req = _in8;
            mk = _in9;
            continue TAIL_CALL_START;
          } else {
            let _in10 = false;
            let _in11 = Common.__default.Set(checks, (req)[_dafny.ZERO], Common.Status.create_Fail());
            let _in12 = _dafny.Seq.Concat(reasons, _dafny.Seq.of((mk)((req)[_dafny.ZERO], _0_c)));
            let _in13 = (req).slice(_dafny.ONE);
            let _in14 = mk;
            allow = _in10;
            checks = _in11;
            reasons = _in12;
            req = _in13;
            mk = _in14;
            continue TAIL_CALL_START;
          }
        }
      }
    };
    static Finalize(st, release, coreAllow, req, mk) {
      return Verdict.__default.Enforce(Verdict.__default.FinalAllow((st).dtor_checks, release, coreAllow), (st).dtor_checks, (st).dtor_reasons, req, mk);
    };
    static WithDeniedFallback(allow, reasons, denied) {
      if ((!(allow)) && ((new BigNumber((reasons).length)).isEqualTo(_dafny.ZERO))) {
        return _dafny.Seq.of(denied);
      } else {
        return reasons;
      }
    };
    static ApplyThreshold(st, thr, tReq, release, th, hookT, why) {
      let _0_r = Verdict.__default.ThresholdRule(tReq, release, th, hookT);
      if ((_0_r).is_ThrOk) {
        return st;
      } else {
        return Verdict.__default.VFail(st, thr, ((_1_why, _2_r) => function () {
          return (_1_why)(_2_r);
        })(why, _0_r));
      }
    };
    static get MaxLifetimeMs() {
      return new BigNumber(3600000);
    };
    static get MaxSkewMs() {
      return new BigNumber(60000);
    };
  };

  $module.AudArg = class AudArg {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_AudAbsent() {
      let $dt = new AudArg(0);
      return $dt;
    }
    static create_AudNull() {
      let $dt = new AudArg(1);
      return $dt;
    }
    static create_AudStr() {
      let $dt = new AudArg(2);
      return $dt;
    }
    get is_AudAbsent() { return this.$tag === 0; }
    get is_AudNull() { return this.$tag === 1; }
    get is_AudStr() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield AudArg.create_AudAbsent();
      yield AudArg.create_AudNull();
      yield AudArg.create_AudStr();
    }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.AudArg.AudAbsent";
      } else if (this.$tag === 1) {
        return "Verdict.AudArg.AudNull";
      } else if (this.$tag === 2) {
        return "Verdict.AudArg.AudStr";
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
      return Verdict.AudArg.create_AudAbsent();
    }
    static Rtd() {
      return class {
        static get Default() {
          return AudArg.Default();
        }
      };
    }
  }

  $module.Validity = class Validity {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_VPass() {
      let $dt = new Validity(0);
      return $dt;
    }
    static create_VBadClock() {
      let $dt = new Validity(1);
      return $dt;
    }
    static create_VNotGreater() {
      let $dt = new Validity(2);
      return $dt;
    }
    static create_VTooLong() {
      let $dt = new Validity(3);
      return $dt;
    }
    static create_VFuture() {
      let $dt = new Validity(4);
      return $dt;
    }
    static create_VExpired() {
      let $dt = new Validity(5);
      return $dt;
    }
    get is_VPass() { return this.$tag === 0; }
    get is_VBadClock() { return this.$tag === 1; }
    get is_VNotGreater() { return this.$tag === 2; }
    get is_VTooLong() { return this.$tag === 3; }
    get is_VFuture() { return this.$tag === 4; }
    get is_VExpired() { return this.$tag === 5; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield Validity.create_VPass();
      yield Validity.create_VBadClock();
      yield Validity.create_VNotGreater();
      yield Validity.create_VTooLong();
      yield Validity.create_VFuture();
      yield Validity.create_VExpired();
    }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.Validity.VPass";
      } else if (this.$tag === 1) {
        return "Verdict.Validity.VBadClock";
      } else if (this.$tag === 2) {
        return "Verdict.Validity.VNotGreater";
      } else if (this.$tag === 3) {
        return "Verdict.Validity.VTooLong";
      } else if (this.$tag === 4) {
        return "Verdict.Validity.VFuture";
      } else if (this.$tag === 5) {
        return "Verdict.Validity.VExpired";
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
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Verdict.Validity.create_VPass();
    }
    static Rtd() {
      return class {
        static get Default() {
          return Validity.Default();
        }
      };
    }
  }

  $module.SuiteViolation = class SuiteViolation {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_NotAllowed() {
      let $dt = new SuiteViolation(0);
      return $dt;
    }
    static create_NoPqCommitment() {
      let $dt = new SuiteViolation(1);
      return $dt;
    }
    static create_PqMismatch() {
      let $dt = new SuiteViolation(2);
      return $dt;
    }
    get is_NotAllowed() { return this.$tag === 0; }
    get is_NoPqCommitment() { return this.$tag === 1; }
    get is_PqMismatch() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield SuiteViolation.create_NotAllowed();
      yield SuiteViolation.create_NoPqCommitment();
      yield SuiteViolation.create_PqMismatch();
    }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.SuiteViolation.NotAllowed";
      } else if (this.$tag === 1) {
        return "Verdict.SuiteViolation.NoPqCommitment";
      } else if (this.$tag === 2) {
        return "Verdict.SuiteViolation.PqMismatch";
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
      return Verdict.SuiteViolation.create_NotAllowed();
    }
    static Rtd() {
      return class {
        static get Default() {
          return SuiteViolation.Default();
        }
      };
    }
  }

  $module.PqResolution = class PqResolution {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_PqRefused() {
      let $dt = new PqResolution(0);
      return $dt;
    }
    static create_PqTrusted() {
      let $dt = new PqResolution(1);
      return $dt;
    }
    static create_PqPinned() {
      let $dt = new PqResolution(2);
      return $dt;
    }
    static create_PqCommitted() {
      let $dt = new PqResolution(3);
      return $dt;
    }
    static create_PqUnbound() {
      let $dt = new PqResolution(4);
      return $dt;
    }
    get is_PqRefused() { return this.$tag === 0; }
    get is_PqTrusted() { return this.$tag === 1; }
    get is_PqPinned() { return this.$tag === 2; }
    get is_PqCommitted() { return this.$tag === 3; }
    get is_PqUnbound() { return this.$tag === 4; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield PqResolution.create_PqRefused();
      yield PqResolution.create_PqTrusted();
      yield PqResolution.create_PqPinned();
      yield PqResolution.create_PqCommitted();
      yield PqResolution.create_PqUnbound();
    }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.PqResolution.PqRefused";
      } else if (this.$tag === 1) {
        return "Verdict.PqResolution.PqTrusted";
      } else if (this.$tag === 2) {
        return "Verdict.PqResolution.PqPinned";
      } else if (this.$tag === 3) {
        return "Verdict.PqResolution.PqCommitted";
      } else if (this.$tag === 4) {
        return "Verdict.PqResolution.PqUnbound";
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
      return Verdict.PqResolution.create_PqRefused();
    }
    static Rtd() {
      return class {
        static get Default() {
          return PqResolution.Default();
        }
      };
    }
  }

  $module.LeafOut = class LeafOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_LeafPass() {
      let $dt = new LeafOut(0);
      return $dt;
    }
    static create_LeafSuiteErr(m) {
      let $dt = new LeafOut(1);
      $dt.m = m;
      return $dt;
    }
    static create_LeafBadSig() {
      let $dt = new LeafOut(2);
      return $dt;
    }
    get is_LeafPass() { return this.$tag === 0; }
    get is_LeafSuiteErr() { return this.$tag === 1; }
    get is_LeafBadSig() { return this.$tag === 2; }
    get dtor_m() { return this.m; }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.LeafOut.LeafPass";
      } else if (this.$tag === 1) {
        return "Verdict.LeafOut.LeafSuiteErr" + "(" + _dafny.toString(this.m) + ")";
      } else if (this.$tag === 2) {
        return "Verdict.LeafOut.LeafBadSig";
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
        return other.$tag === 1 && _dafny.areEqual(this.m, other.m);
      } else if (this.$tag === 2) {
        return other.$tag === 2;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Verdict.LeafOut.create_LeafPass();
    }
    static Rtd() {
      return class {
        static get Default() {
          return LeafOut.Default();
        }
      };
    }
  }

  $module.CapChainOut = class CapChainOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_CapEmpty() {
      let $dt = new CapChainOut(0);
      return $dt;
    }
    static create_CapRootNotGrant() {
      let $dt = new CapChainOut(1);
      return $dt;
    }
    static create_CapWalked(r) {
      let $dt = new CapChainOut(2);
      $dt.r = r;
      return $dt;
    }
    get is_CapEmpty() { return this.$tag === 0; }
    get is_CapRootNotGrant() { return this.$tag === 1; }
    get is_CapWalked() { return this.$tag === 2; }
    get dtor_r() { return this.r; }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.CapChainOut.CapEmpty";
      } else if (this.$tag === 1) {
        return "Verdict.CapChainOut.CapRootNotGrant";
      } else if (this.$tag === 2) {
        return "Verdict.CapChainOut.CapWalked" + "(" + _dafny.toString(this.r) + ")";
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
        return other.$tag === 2 && _dafny.areEqual(this.r, other.r);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Verdict.CapChainOut.create_CapEmpty();
    }
    static Rtd() {
      return class {
        static get Default() {
          return CapChainOut.Default();
        }
      };
    }
  }

  $module.HookOut = class HookOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_HookNotEnforced() {
      let $dt = new HookOut(0);
      return $dt;
    }
    static create_HookPass() {
      let $dt = new HookOut(1);
      return $dt;
    }
    static create_HookFail() {
      let $dt = new HookOut(2);
      return $dt;
    }
    get is_HookNotEnforced() { return this.$tag === 0; }
    get is_HookPass() { return this.$tag === 1; }
    get is_HookFail() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield HookOut.create_HookNotEnforced();
      yield HookOut.create_HookPass();
      yield HookOut.create_HookFail();
    }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.HookOut.HookNotEnforced";
      } else if (this.$tag === 1) {
        return "Verdict.HookOut.HookPass";
      } else if (this.$tag === 2) {
        return "Verdict.HookOut.HookFail";
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
      return Verdict.HookOut.create_HookNotEnforced();
    }
    static Rtd() {
      return class {
        static get Default() {
          return HookOut.Default();
        }
      };
    }
  }

  $module.CoreSt = class CoreSt {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_CoreSt(checks, reason, terminal) {
      let $dt = new CoreSt(0);
      $dt.checks = checks;
      $dt.reason = reason;
      $dt.terminal = terminal;
      return $dt;
    }
    get is_CoreSt() { return this.$tag === 0; }
    get dtor_checks() { return this.checks; }
    get dtor_reason() { return this.reason; }
    get dtor_terminal() { return this.terminal; }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.CoreSt.CoreSt" + "(" + _dafny.toString(this.checks) + ", " + _dafny.toString(this.reason) + ", " + _dafny.toString(this.terminal) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.checks, other.checks) && _dafny.areEqual(this.reason, other.reason) && this.terminal === other.terminal;
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Verdict.CoreSt.create_CoreSt(_dafny.Seq.of(), Common.Option.Default(), false);
    }
    static Rtd() {
      return class {
        static get Default() {
          return CoreSt.Default();
        }
      };
    }
  }

  $module.VSt = class VSt {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_VSt(checks, reasons) {
      let $dt = new VSt(0);
      $dt.checks = checks;
      $dt.reasons = reasons;
      return $dt;
    }
    get is_VSt() { return this.$tag === 0; }
    get dtor_checks() { return this.checks; }
    get dtor_reasons() { return this.reasons; }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.VSt.VSt" + "(" + _dafny.toString(this.checks) + ", " + _dafny.toString(this.reasons) + ")";
      } else  {
        return "<unexpected>";
      }
    }
    equals(other) {
      if (this === other) {
        return true;
      } else if (this.$tag === 0) {
        return other.$tag === 0 && _dafny.areEqual(this.checks, other.checks) && _dafny.areEqual(this.reasons, other.reasons);
      } else  {
        return false; // unexpected
      }
    }
    static Default() {
      return Verdict.VSt.create_VSt(_dafny.Seq.of(), _dafny.Seq.of());
    }
    static Rtd() {
      return class {
        static get Default() {
          return VSt.Default();
        }
      };
    }
  }

  $module.PlanOut = class PlanOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_PlanNotEnforced() {
      let $dt = new PlanOut(0);
      return $dt;
    }
    static create_PlanPass() {
      let $dt = new PlanOut(1);
      return $dt;
    }
    static create_PlanMismatch() {
      let $dt = new PlanOut(2);
      return $dt;
    }
    static create_PlanUnauthorized() {
      let $dt = new PlanOut(3);
      return $dt;
    }
    get is_PlanNotEnforced() { return this.$tag === 0; }
    get is_PlanPass() { return this.$tag === 1; }
    get is_PlanMismatch() { return this.$tag === 2; }
    get is_PlanUnauthorized() { return this.$tag === 3; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield PlanOut.create_PlanNotEnforced();
      yield PlanOut.create_PlanPass();
      yield PlanOut.create_PlanMismatch();
      yield PlanOut.create_PlanUnauthorized();
    }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.PlanOut.PlanNotEnforced";
      } else if (this.$tag === 1) {
        return "Verdict.PlanOut.PlanPass";
      } else if (this.$tag === 2) {
        return "Verdict.PlanOut.PlanMismatch";
      } else if (this.$tag === 3) {
        return "Verdict.PlanOut.PlanUnauthorized";
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
      return Verdict.PlanOut.create_PlanNotEnforced();
    }
    static Rtd() {
      return class {
        static get Default() {
          return PlanOut.Default();
        }
      };
    }
  }

  $module.BeaconOut = class BeaconOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_BeaconNotEnforced() {
      let $dt = new BeaconOut(0);
      return $dt;
    }
    static create_BeaconPass() {
      let $dt = new BeaconOut(1);
      return $dt;
    }
    static create_BeaconRejected() {
      let $dt = new BeaconOut(2);
      return $dt;
    }
    static create_BeaconReplayed() {
      let $dt = new BeaconOut(3);
      return $dt;
    }
    static create_BeaconUnbound() {
      let $dt = new BeaconOut(4);
      return $dt;
    }
    get is_BeaconNotEnforced() { return this.$tag === 0; }
    get is_BeaconPass() { return this.$tag === 1; }
    get is_BeaconRejected() { return this.$tag === 2; }
    get is_BeaconReplayed() { return this.$tag === 3; }
    get is_BeaconUnbound() { return this.$tag === 4; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield BeaconOut.create_BeaconNotEnforced();
      yield BeaconOut.create_BeaconPass();
      yield BeaconOut.create_BeaconRejected();
      yield BeaconOut.create_BeaconReplayed();
      yield BeaconOut.create_BeaconUnbound();
    }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.BeaconOut.BeaconNotEnforced";
      } else if (this.$tag === 1) {
        return "Verdict.BeaconOut.BeaconPass";
      } else if (this.$tag === 2) {
        return "Verdict.BeaconOut.BeaconRejected";
      } else if (this.$tag === 3) {
        return "Verdict.BeaconOut.BeaconReplayed";
      } else if (this.$tag === 4) {
        return "Verdict.BeaconOut.BeaconUnbound";
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
      return Verdict.BeaconOut.create_BeaconNotEnforced();
    }
    static Rtd() {
      return class {
        static get Default() {
          return BeaconOut.Default();
        }
      };
    }
  }

  $module.RevOut = class RevOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_RevNoServerClass() {
      let $dt = new RevOut(0);
      return $dt;
    }
    static create_RevPass() {
      let $dt = new RevOut(1);
      return $dt;
    }
    static create_RevLessRestrictive() {
      let $dt = new RevOut(2);
      return $dt;
    }
    get is_RevNoServerClass() { return this.$tag === 0; }
    get is_RevPass() { return this.$tag === 1; }
    get is_RevLessRestrictive() { return this.$tag === 2; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield RevOut.create_RevNoServerClass();
      yield RevOut.create_RevPass();
      yield RevOut.create_RevLessRestrictive();
    }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.RevOut.RevNoServerClass";
      } else if (this.$tag === 1) {
        return "Verdict.RevOut.RevPass";
      } else if (this.$tag === 2) {
        return "Verdict.RevOut.RevLessRestrictive";
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
      return Verdict.RevOut.create_RevNoServerClass();
    }
    static Rtd() {
      return class {
        static get Default() {
          return RevOut.Default();
        }
      };
    }
  }

  $module.ThrOut = class ThrOut {
    constructor(tag) {
      this.$tag = tag;
    }
    static create_ThrOk() {
      let $dt = new ThrOut(0);
      return $dt;
    }
    static create_ThrBelow() {
      let $dt = new ThrOut(1);
      return $dt;
    }
    static create_ThrRejected() {
      let $dt = new ThrOut(2);
      return $dt;
    }
    static create_ThrNoVerifier() {
      let $dt = new ThrOut(3);
      return $dt;
    }
    get is_ThrOk() { return this.$tag === 0; }
    get is_ThrBelow() { return this.$tag === 1; }
    get is_ThrRejected() { return this.$tag === 2; }
    get is_ThrNoVerifier() { return this.$tag === 3; }
    static get AllSingletonConstructors() {
      return this.AllSingletonConstructors_();
    }
    static *AllSingletonConstructors_() {
      yield ThrOut.create_ThrOk();
      yield ThrOut.create_ThrBelow();
      yield ThrOut.create_ThrRejected();
      yield ThrOut.create_ThrNoVerifier();
    }
    toString() {
      if (this.$tag === 0) {
        return "Verdict.ThrOut.ThrOk";
      } else if (this.$tag === 1) {
        return "Verdict.ThrOut.ThrBelow";
      } else if (this.$tag === 2) {
        return "Verdict.ThrOut.ThrRejected";
      } else if (this.$tag === 3) {
        return "Verdict.ThrOut.ThrNoVerifier";
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
      return Verdict.ThrOut.create_ThrOk();
    }
    static Rtd() {
      return class {
        static get Default() {
          return ThrOut.Default();
        }
      };
    }
  }
  return $module;
})(); // end of module Verdict
let _module = (function() {
  let $module = {};

  return $module;
})(); // end of module _module

// ---- exports (appended by formal/dafny/build.sh; not part of the Dafny-generated text above) ----
module.exports = { _dafny, Common, Chain, Caveats, Threshold, Replay, Verdict };
