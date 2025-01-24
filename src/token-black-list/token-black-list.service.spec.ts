import { Test, TestingModule } from '@nestjs/testing';
import { TokenBlackListService } from './token-black-list.service';

describe('TokenBlackListService', () => {
  let service: TokenBlackListService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [TokenBlackListService],
    }).compile();

    service = module.get<TokenBlackListService>(TokenBlackListService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
