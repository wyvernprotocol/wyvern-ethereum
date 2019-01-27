/* global artifacts:false, it:false, contract:false, assert:false */

const WyvernExchange = artifacts.require('WyvernExchange')
const WyvernRegistry = artifacts.require('WyvernRegistry')

const { wrap, hashOrder, hashToSign, ZERO_ADDRESS, ZERO_BYTES32 } = require('./aux.js')

contract('WyvernExchange', (accounts) => {
  const withExchangeAndRegistry = () => {
    return WyvernExchange
      .deployed()
      .then(instance => {
        return WyvernRegistry
          .deployed()
          .then(registryInstance => {
            return {exchange: wrap(instance), registry: registryInstance}
          })
      })
  }

  it('should be deployed', () => {
    return withExchangeAndRegistry()
      .then(() => {})
  })

  it('should correctly hash order', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[0], staticTarget: ZERO_ADDRESS, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '0', salt: '0'}
        return exchange.hashOrder(example).then(hash => {
          assert.equal(hashOrder(example), hash, 'Incorrect order hash')
        })
      })
  })

  it('should correctly hash order to sign', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[0], staticTarget: ZERO_ADDRESS, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '0', salt: '0'}
        return exchange.hashToSign(example).then(hash => {
          assert.equal(hashToSign(example, exchange.inst.address), hash, 'Incorrect order hash')
        })
      })
  })

  it('should not allow set-fill to same fill', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[1], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '6'}
        return exchange.setOrderFill(example, '0', {from: accounts[1]}).then(() => {
          assert.equal(true, false, 'should not have suceeded')
        }).catch(err => {
          assert.include(err.message, 'Returned error: VM Exception while processing transaction: revert', 'Incorrect error')
        })
      })
  })

  it('should validate valid order parameters', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[0], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '0'}
        return exchange.validateOrderParameters(example).then(valid => {
          assert.equal(true, valid, 'Should have validated')
        })
      })
  })

  it('should not validate order parameters with invalid staticTarget', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[0], staticTarget: ZERO_ADDRESS, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '0'}
        return exchange.validateOrderParameters(example).then(valid => {
          assert.equal(false, valid, 'Should not have validated')
        })
      })
  })

  it('should not validate order parameters with listingTime after now', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[0], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '1000000000000', expirationTime: '1000000000000', salt: '0'}
        return exchange.validateOrderParameters(example).then(valid => {
          assert.equal(false, valid, 'Should not have validated')
        })
      })
  })

  it('should not validate order parameters with expirationTime before now', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[0], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '0', salt: '0'}
        return exchange.validateOrderParameters(example).then(valid => {
          assert.equal(false, valid, 'Should not have validated')
        })
      })
  })

  it('should validate valid authorization by signature', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[1], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '100230'}
        return exchange.sign(example, accounts[1]).then(sig => {
          const hash = hashOrder(example)
          return exchange.validateOrderAuthorization(hash, accounts[0], sig).then(valid => {
            assert.equal(true, valid, 'Should have validated')
          })
        })
      })
  })

  it('should not allow approval twice', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[1], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '1010'}
        return exchange.approveOrder(example, false, {from: accounts[1]}).then(() => {
          return exchange.approveOrder(example, false, {from: accounts[1]}).then(() => {
            assert.equal(true, false, 'should not have succeeded')
          }).catch(err => {
            assert.include(err.message, 'Returned error: VM Exception while processing transaction: revert', 'Incorrect error')
          })
        })
      })
  })

  it('should not allow approval from another user', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[1], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '10101234'}
        return exchange.approveOrder(example, false, {from: accounts[2]}).then(() => {
          assert.equal(true, false, 'should not have succeeded')
        }).catch(err => {
          assert.include(err.message, 'Returned error: VM Exception while processing transaction: revert', 'Incorrect error')
        })
      })
  })

  it('should validate valid authorization by approval', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[1], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '10'}
        return exchange.approveOrder(example, false, {from: accounts[1]}).then(() => {
          const hash = hashOrder(example)
          return exchange.validateOrderAuthorization(hash, accounts[0], {v: 27, r: ZERO_BYTES32, s: ZERO_BYTES32}).then(valid => {
            assert.equal(true, valid, 'Should have validated')
          })
        })
      })
  })

  it('should validate valid authorization by hash-approval', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[1], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '1'}
        const hash = hashOrder(example)
        return exchange.approveOrderHash(hash, {from: accounts[1]}).then(() => {
          return exchange.validateOrderAuthorization(hash, accounts[0], {v: 27, r: ZERO_BYTES32, s: ZERO_BYTES32}).then(valid => {
            assert.equal(true, valid, 'Should have validated')
          })
        })
      })
  })

  it('should validate valid authorization by maker', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[0], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '5'}
        const hash = hashOrder(example)
        return exchange.validateOrderAuthorization(hash, accounts[0], {v: 27, r: ZERO_BYTES32, s: ZERO_BYTES32}, {from: accounts[0]}).then(valid => {
          assert.equal(true, valid, 'Should have validated')
        })
      })
  })

  it('should validate valid authorization by cache', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[1], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '6'}
        return exchange.setOrderFill(example, '2', {from: accounts[1]}).then(() => {
          const hash = hashOrder(example)
          return exchange.validateOrderAuthorization(hash, accounts[0], {v: 27, r: ZERO_BYTES32, s: ZERO_BYTES32}, {from: accounts[0]}).then(valid => {
            assert.equal(true, valid, 'Should have validated')
          })
        })
      })
  })

  it('should not validate authorization without signature', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[1], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '0'}
        const hash = hashOrder(example)
        return exchange.validateOrderAuthorization(hash, accounts[1], {v: 27, r: ZERO_BYTES32, s: ZERO_BYTES32}).then(valid => {
          assert.equal(false, valid, 'Should not have validated')
        })
      })
  })

  it('should not validate cancelled order', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[0], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '20'}
        return exchange.sign(example, accounts[0]).then(sig => {
          return exchange.setOrderFill(example, 1).then(() => {
            return exchange.validateOrderParameters(example).then(valid => {
              assert.equal(false, valid, 'Should not have validated')
            })
          })
        })
      })
  })

  it('should allow order cancellation by maker', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[0], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '3'}
        return exchange.setOrderFill(example, 1).then(() => {})
      })
  })

  it('should allow order cancellation by non-maker', () => {
    return withExchangeAndRegistry()
      .then(({exchange, registry}) => {
        const example = {maker: accounts[1], staticTarget: exchange.inst.address, staticSelector: '0x00000000', staticExtradata: '0x', maximumFill: '1', listingTime: '0', expirationTime: '1000000000000', salt: '4'}
        return exchange.setOrderFill(example, 1).then(() => {})
      })
  })
})
