/** @format */
// Copyright 2020 Stanislav V Vyaliy.  All rights reserved.

import { Attribute } from './attribute';

export class Change {
  private _modification: Attribute | Record<any, any>;

  private _operation: number;

  get operation(): 'add' | 'delete' | 'replace' {
    switch (this._operation) {
      case 0x00:
        return 'add';
      case 0x01:
        return 'delete';
      case 0x02:
        return 'replace';
      default:
        throw new Error(`0x${this._operation.toString(16)} is invalid`);
    }
  }

  set operation(value: 'add' | 'delete' | 'replace') {
    switch (value) {
      case 'add':
        this._operation = 0x00;
        break;
      case 'delete':
        this._operation = 0x01;
        break;
      case 'replace':
        this._operation = 0x02;
        break;
      default:
        throw new Error(`Invalid operation type: 0x${Number(value).toString(16)}`);
    }
  }

  get modification(): Attribute | Record<any, any> {
    return this._modification;
  }

  set modification(value: Attribute | Record<any, any>) {
    if (value instanceof Attribute || Attribute.isAttribute(value)) {
      this._modification = value;
      return;
    }

    // Does it have an attribute-like structure
    if (Object.keys(value).length === 2 && typeof value.type === 'string' && Array.isArray(value.vals)) {
      this._modification = new Attribute({
        type: value.type,
        vals: value.vals,
      });
      return;
    }

    const keys = Object.keys(value);
    if (keys.length > 1) {
      throw new Error('Only one attribute per Change allowed');
    } else if (keys.length === 0) {
      return;
    }

    const k = keys[0];
    const _attribute = new Attribute({ type: k });
    if (Array.isArray(value[k])) {
      value[k].forEach((v: any): void => {
        _attribute.addValue(v);
      });
    } else {
      _attribute.addValue(value[k]);
    }
    this._modification = _attribute;
  }

  constructor(options: Record<any, any> = { operation: 'add' }) {
    this._modification = {};
    this.operation = options.operation || options.type || 'add';
    this.modification = options.modification || {};
  }

  isChange = (change: Change | Record<any, any>): boolean => {
    if (!change || typeof change !== 'object') {
      return false;
    }

    if (
      change instanceof Change ||
      (typeof change.toBer === 'function' && change.modification !== undefined && change.operation !== undefined)
    ) {
      return true;
    }

    return false;
  };

  compare = (a: Change | Record<any, any>, b: Change | Record<any, any>): number => {
    if (!this.isChange(a) || !this.isChange(b)) {
      throw new TypeError('can only compare Changes');
    }

    if (a.operation < b.operation) return -1;
    if (a.operation > b.operation) return 1;

    return Attribute.compare(a.modification, b.modification);
  };

  /**
   * Apply a Change to properties of an object.
   *
   * @param {Object} change the change to apply.
   * @param {Object} obj the object to apply it to.
   * @param {Boolean} scalar convert single-item arrays to scalars. Default: false
   */
  apply = (
    change: Record<any, any> = { operation: 'add', modification: { type: '' } },
    object: Record<any, any>,
    scalar: any,
  ): any => {
    const { type } = change.modification;
    const { vals } = change.modification;
    let data = object[type];
    if (data !== undefined) {
      if (!Array.isArray(data)) {
        data = [data];
      }
    } else {
      data = [];
    }
    switch (change.operation) {
      case 'replace':
        if (vals.length === 0) {
          // replace empty is a delete
          delete object[type];
          return object;
        }
        data = vals;

        break;
      case 'add': {
        // add only new unique entries
        const newValues = vals.filter((entry: any) => {
          return !data.includes(entry);
        });
        data = data.concat(newValues);
        break;
      }
      case 'delete':
        data = data.filter((entry: any) => {
          return !vals.includes(entry);
        });
        if (data.length === 0) {
          // Erase the attribute if empty
          delete object[type];
          return object;
        }
        break;
      default:
        break;
    }
    if (scalar && data.length === 1) {
      // store single-value outputs as scalars, if requested
      // eslint-disable-next-line prefer-destructuring
      object[type] = data[0];
    } else {
      object[type] = data;
    }
    return object;
  };

  parse = (ber: any): boolean => {
    if (!ber) {
      return false;
    }

    ber.readSequence();
    this._operation = ber.readEnumeration();
    this._modification = new Attribute();
    this._modification.parse(ber);

    return true;
  };

  toBer = (ber: any): any => {
    if (!ber) {
      throw new TypeError('ldapjs Change toBer: ber is undefined');
    }

    ber.startSequence();
    ber.writeEnumeration(this._operation);
    ber = this._modification?.toBer(ber);
    ber.endSequence();

    return ber;
  };

  json = (): Record<any, any> => ({
    operation: this.operation,
    modification: this._modification ? this._modification.json : {},
  });
}
