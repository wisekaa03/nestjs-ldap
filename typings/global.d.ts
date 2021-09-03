/** @format */
/* eslint max-len:0, no-underscore-dangle:0, @typescript-eslint/ban-types:0, @typescript-eslint/no-explicit-any:0, @typescript-eslint/no-empty-interface:0 */

declare const __DEV__: boolean;
declare const __PRODUCTION__: boolean;
declare const __TEST__: boolean;
declare const __SERVER__: boolean;

declare module 'cache-manager-redis-store';

declare namespace NodeJS {
  interface GlobalFetch {}
  interface Global extends NodeJS.Global, GlobalFetch {
    fetch: Function;
    __SERVER__?: boolean;
    __DEV__?: boolean;
    __PRODUCTION__?: boolean;
    __TEST__?: boolean;
  }
}

export declare global {
  interface globalThis {
    __SERVER__?: boolean;
    __DEV__?: boolean;
    __PRODUCTION__?: boolean;
    __TEST__?: boolean;
  }
}

declare module '*.woff2' {
  const content: string;
  const className: string;
  export = content;
}

declare module '*.svg' {
  const content: string;
  const className: string;
  export = content;
}

declare module '*.svg?inline' {
  const content: string;
  const className: string;
  export = content;
}

declare module '*.png' {
  const content: string;
  const className: string;
  export = content;
}

declare module '*.png?inline' {
  const content: string;
  const className: string;
  export = content;
}

declare module '*.webp' {
  const content: string;
  const className: string;
  export = content;
}
declare module '*.jpg' {
  const content: string;
  const className: string;
  export = content;
}

declare module '*.jpeg' {
  const content: string;
  const className: string;
  export = content;
}

declare module '*.gif' {
  const content: string;
  const className: string;
  export default content;
}
