/** @format */

import { Test, TestingModule } from '@nestjs/testing';
import { WINSTON_MODULE_PROVIDER } from 'nest-winston';
import { LdapService } from './ldap.service';
import { LDAP_OPTIONS } from './ldap.interface';

const serviceMock = jest.fn(() => ({}));

describe(LdapService.name, () => {
  let ldap: LdapService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [],
      providers: [
        { provide: WINSTON_MODULE_PROVIDER, useValue: serviceMock },
        { provide: LDAP_OPTIONS, useValue: { options: { cache: false }, domains: [] } },
        LdapService,
      ],
    }).compile();

    ldap = module.get<LdapService>(LdapService);
  });

  it('should be defined', () => {
    expect(ldap).toBeDefined();
  });
});
