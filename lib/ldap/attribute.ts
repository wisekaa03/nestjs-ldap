/** @format */
/* eslint-disable import/no-extraneous-dependencies */

// Copyright 2020 Stanislav V Vyaliy.  All rights reserved.

import asn1 from 'asn1';

import { Protocol } from './protocol';

export class Attribute {
  public _vals: Record<any, any>;

  public type: any;

  /**
   * Get vals
   *
   * @returns {string | Buffer}
   */
  get vals(): string | Buffer {
    return this._vals.map((v: any) => v.toString(this.bufferEncoding(this.type)));
  }

  /**
   * Set vals
   *
   * @param {string | Buffer} vals
   */
  set vals(vals: string | Buffer) {
    this._vals = [];
    if (Array.isArray(vals)) {
      vals.forEach((v) => {
        this.addValue(v);
      });
    } else {
      this.addValue(vals);
    }
  }

  /**
   * Get buffers
   *
   * @returns {Record<any, any>} buffers
   */
  get buffers(): Record<any, any> {
    return this._vals;
  }

  /**
   * Get json
   *
   * @returns {Record<string, any>} { type, vals }
   */
  get json(): Record<string, any> {
    return {
      type: this.type,
      vals: this.vals,
    };
  }

  constructor(options: Record<any, any> = { type: '' }) {
    if (options.type && typeof options.type !== 'string') {
      throw new TypeError('options.type must be a string');
    }

    this.type = options.type || '';

    if (options.vals !== undefined && options.vals !== null) {
      this.vals = options.vals;
    }
  }

  bufferEncoding = (type: string): 'base64' | 'utf8' => (/;binary$/.test(type) ? 'base64' : 'utf8');

  addValue = (val: Buffer | string): void => {
    if (Buffer.isBuffer(val)) {
      this._vals.push(val);
    } else {
      this._vals.push(Buffer.from(val, this.bufferEncoding(this.type)));
    }
  };

  static isAttribute = (attr: Attribute | Record<any, any>): boolean => {
    if (attr instanceof Attribute) {
      return true;
    }

    if (
      typeof attr.toBer === 'function' &&
      typeof attr.type === 'string' &&
      Array.isArray(attr.vals) &&
      attr.vals.filter((item) => typeof item === 'string' || Buffer.isBuffer(item)).length === attr.vals.length
    ) {
      return true;
    }

    return false;
  };

  static compare = (a: Attribute | Record<any, any>, b: Attribute | Record<any, any>): number => {
    if (!Attribute.isAttribute(a) || !Attribute.isAttribute(b)) {
      throw new TypeError('can only compare Attributes');
    }

    if (a.type < b.type) return -1;
    if (a.type > b.type) return 1;
    if (a.vals.length < b.vals.length) return -1;
    if (a.vals.length > b.vals.length) return 1;

    for (let i = 0; i < a.vals.length; i++) {
      if (a.vals[i] < b.vals[i]) return -1;
      if (a.vals[i] > b.vals[i]) return 1;
    }

    return 0;
  };

  parse = (ber: any): boolean => {
    if (!ber) {
      throw new TypeError('ldapjs Attribute parse: ber is undefined');
    }

    ber.readSequence();
    this.type = ber.readString();

    if (ber.peek() === Protocol.LBER_SET) {
      if (ber.readSequence(Protocol.LBER_SET)) {
        const end = ber.offset + ber.length;
        while (ber.offset < end) this._vals.push(ber.readString(asn1.Ber.OctetString, true));
      }
    }

    return true;
  };

  toString = (): string => JSON.stringify(this.json);

  toBer = (ber: any): any => {
    if (!ber) {
      throw new TypeError('ldapjs Attribute toBer: ber is undefined');
    }

    ber.startSequence();
    ber.writeString(this.type);
    ber.startSequence(Protocol.LBER_SET);
    if (this._vals.length) {
      this._vals.forEach((b: any) => {
        ber.writeByte(asn1.Ber.OctetString);
        ber.writeLength(b.length);
        for (let i = 0; i < b.length; i++) ber.writeByte(b[i]);
      });
    } else {
      ber.writeStringArray([]);
    }
    ber.endSequence();
    ber.endSequence();

    return ber;
  };
}

/* eslint-enable import/no-extraneous-dependencies */
