/** @format */

//#region Imports NPM
import { DynamicModule, Module, Provider, Type, Global } from '@nestjs/common';
//#endregion
//#region Imports Local
// import { ConfigModule } from '@app/config';
import { LdapService } from './ldap.service';
import { LDAP_OPTIONS, LdapModuleOptions, LdapModuleAsyncOptions, LdapOptionsFactory } from './ldap.interface';
//#endregion

@Global()
@Module({
  imports: [],
  providers: [LdapService],
  exports: [LdapService],
})
export class LdapModule {
  static register(options: LdapModuleOptions): DynamicModule {
    return {
      module: LdapModule,
      providers: [{ provide: LDAP_OPTIONS, useValue: options || {} }, LdapService],
    };
  }

  static registerAsync(options: LdapModuleAsyncOptions): DynamicModule {
    return {
      module: LdapModule,
      imports: options.imports || [],
      providers: this.createAsyncProviders(options),
    };
  }

  private static createAsyncProviders(options: LdapModuleAsyncOptions): Provider[] {
    if (options.useExisting || options.useFactory) {
      return [this.createAsyncOptionsProvider(options)];
    }
    return [
      this.createAsyncOptionsProvider(options),
      {
        provide: options.useClass as Type<LdapOptionsFactory>,
        useClass: options.useClass as Type<LdapOptionsFactory>,
      },
    ];
  }

  private static createAsyncOptionsProvider(options: LdapModuleAsyncOptions): Provider {
    if (options.useFactory) {
      return {
        provide: LDAP_OPTIONS,
        useFactory: options.useFactory,
        inject: options.inject || [],
      };
    }
    return {
      provide: LDAP_OPTIONS,
      useFactory: async (optionsFactory: LdapOptionsFactory) => optionsFactory.createLdapOptions(),
      inject: [(options.useExisting as Type<LdapOptionsFactory>) || (options.useClass as Type<LdapOptionsFactory>)],
    };
  }
}
