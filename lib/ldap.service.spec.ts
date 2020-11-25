/** @format */

import { Test, TestingModule } from '@nestjs/testing';
import { Logger } from '@nestjs/common';
import { LdapService } from './ldap.service';
import { LDAP_OPTIONS } from './ldap.interface';

const serviceMock = jest.fn(() => ({}));

describe(LdapService.name, () => {
  let ldap: LdapService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      imports: [],
      providers: [
        { provide: LDAP_OPTIONS, useValue: { options: {}, cache: false, domains: [] } },
        { provide: Logger, useValue: serviceMock },
        LdapService,
      ],
    }).compile();

    ldap = module.get<LdapService>(LdapService);
  });

  it('should be defined', () => {
    expect(ldap).toBeDefined();
  });
});
