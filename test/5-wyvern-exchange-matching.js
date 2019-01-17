/* global artifacts:false, it:false, contract:false, assert:false */

const WyvernAtomicizer = artifacts.require('WyvernAtomicizer')
const WyvernExchange = artifacts.require('WyvernExchange')
const WyvernStatic = artifacts.require('WyvernStatic')
const WyvernRegistry = artifacts.require('WyvernRegistry')
const TestERC20 = artifacts.require('TestERC20')
const TestERC721 = artifacts.require('TestERC721')

const Web3 = require('web3')
const provider = new Web3.providers.HttpProvider('http://localhost:8545')
const web3 = new Web3(provider)

const { wrap, hashOrder, ZERO_BYTES32, randomUint } = require('./aux.js')

const nullSig = {v: 27, r: ZERO_BYTES32, s: ZERO_BYTES32}

contract('WyvernExchange', (accounts) => {
  const withContracts = () => {
    return WyvernExchange
      .deployed()
      .then(exchange => {
        exchange = wrap(exchange)
        return WyvernStatic
          .deployed()
          .then(statici => {
            return WyvernRegistry
              .deployed()
              .then(registry => {
                return TestERC20
                  .deployed()
                  .then(erc20 => {
                    return TestERC721
                      .deployed()
                      .then(erc721 => {
                        return WyvernAtomicizer
                          .deployed()
                          .then(atomicizer => {
                            return { atomicizer, exchange, statici, registry, erc20, erc721 }
                          })
                      })
                  })
              })
          })
      })
  }

  const withAsymmetricalTokens = () => {
    return withContracts().then(({erc20, erc721}) => {
      return erc721.transferFrom(accounts[0], accounts[1], 1).then(() => {
        return {nfts: [1, 2, 3]}
      })
    })
  }

  const withSomeTokens = () => {
    return withContracts().then(({erc20, erc721}) => {
      const amount = randomUint()
      return erc20.mint(accounts[0], amount).then(() => {
        return {tokens: amount, nfts: [1, 2, 3]}
      })
    })
  }

  it('should allow proxy transfer approval', () => {
    return withContracts().then(({registry, erc20, erc721}) => {
      return registry.registerProxy({from: accounts[0]}).then(() => {
        return registry.proxies(accounts[0]).then(proxy => {
          return erc20.approve(proxy, 100000).then(() => {
            return erc721.setApprovalForAll(proxy, true)
          })
        })
      })
    })
  })

  it('should allow proxy registration', () => {
    return withContracts().then(({registry}) => {
      return registry.registerProxy({from: accounts[6]}).then(() => {
        return registry.proxies(accounts[6]).then(ret => {
          assert.equal(true, ret.length > 0, 'no proxy address')
        })
      })
    })
  })

  it('should match any-any nop order', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[0], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: '0'}
        const two = {registry: registry.address, maker: accounts[0], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: '1'}
        const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
        return exchange.atomicMatch(one, nullSig, call, two, nullSig, call, ZERO_BYTES32).then(() => {
        })
      })
  })

  it('should match any-any nop order twice with no fill', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('anyNoFill(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[0], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const two = {registry: registry.address, maker: accounts[0], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
        return exchange.atomicMatch(one, nullSig, call, two, nullSig, call, ZERO_BYTES32).then(() => {
          return exchange.atomicMatch(one, nullSig, call, two, nullSig, call, ZERO_BYTES32).then(() => {
          })
        })
      })
  })

  it('should match exactly twice with two-fill', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('anyAddOne(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '2', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const two = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '2', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
        return exchange.sign(one, accounts[6]).then(oneSig => {
          return exchange.sign(two, accounts[6]).then(twoSig => {
            return exchange.atomicMatch(one, oneSig, call, two, twoSig, call, ZERO_BYTES32).then(() => {
              return exchange.atomicMatch(one, oneSig, call, two, twoSig, call, ZERO_BYTES32).then(() => {
                return exchange.atomicMatch(one, oneSig, call, two, twoSig, call, ZERO_BYTES32).then(() => {
                  assert.equal(true, false, 'should not have succeeded')
                }).catch(err => {
                  assert.equal(err.message, 'Returned error: VM Exception while processing transaction: revert', 'Incorrect error')
                })
              })
            })
          })
        })
      })
  })

  it('should not self-match', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[0], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: '0'}
        const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
        return exchange.atomicMatch(one, nullSig, call, one, nullSig, call, ZERO_BYTES32).then(() => {
          assert.equal(true, false, 'should not have succeeded')
        }).catch(err => {
          assert.equal(err.message, 'Returned error: VM Exception while processing transaction: revert', 'Incorrect error')
        })
      })
  })

  it('should not match any-any reentrant order', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[0], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: '4'}
        const two = {registry: registry.address, maker: accounts[0], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: '5'}
        const exchangec = new web3.eth.Contract(exchange.inst.abi, exchange.inst.address)
        const call1 = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
        const data = exchangec.methods.atomicMatch_(
          [one.registry, one.maker, one.staticTarget, call1.target, two.registry, two.maker, two.staticTarget, call1.target],
          [one.maximumFill, one.listingTime, one.expirationTime, one.salt, two.maximumFill, two.listingTime, two.expirationTime, two.salt],
          one.staticExtradata, call1.data, two.staticExtradata, call1.data,
          [nullSig.v, call1.howToCall, nullSig.v, call1.howToCall],
          [nullSig.r, nullSig.s, nullSig.r, nullSig.s, ZERO_BYTES32]).encodeABI()
        const call2 = {target: exchange.inst.address, howToCall: 0, data: data}
        return exchange.atomicMatch(one, nullSig, call1, two, nullSig, call2, ZERO_BYTES32).then(() => {
          assert.equal(true, false, 'should not have succeeded')
        }).catch(err => {
          assert.equal(err.message, 'Returned error: VM Exception while processing transaction: invalid opcode', 'Incorrect error')
        })
      })
  })

  it('should match nft-nft swap order', () => {
    return withContracts()
      .then(({atomicizer, exchange, registry, statici, erc20, erc721}) => {
        return withAsymmetricalTokens()
          .then(({ nfts }) => {
            const atomicizerc = new web3.eth.Contract(atomicizer.abi, atomicizer.address)
            const erc721c = new web3.eth.Contract(erc721.abi, erc721.address)
            // const func = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
            const func = web3.eth.abi.encodeFunctionSignature('swapOneForOne(address[2],uint256[2],address[7],uint8[2],uint256[6],bytes,bytes)')
            const paramsOne = web3.eth.abi.encodeParameters(
              ['address[2]', 'uint256[2]'],
              [[erc721.address, erc721.address], [3, 1]]
            )
            const paramsTwo = web3.eth.abi.encodeParameters(
              ['address[2]', 'uint256[2]'],
              [[erc721.address, erc721.address], [1, 3]]
            )

            const one = {registry: registry.address, maker: accounts[0], staticTarget: statici.address, staticExtradata: func + paramsOne.slice(2), maximumFill: '1', listingTime: '0', expirationTime: '10000000000', salt: '2'}
            const two = {registry: registry.address, maker: accounts[1], staticTarget: statici.address, staticExtradata: func + paramsTwo.slice(2), maximumFill: '1', listingTime: '0', expirationTime: '10000000000', salt: '3'}

            console.warn(one.staticExtradata)
            console.warn(two.staticExtradata)

            let firstData = erc721c.methods.transferFrom(accounts[0], accounts[1], 3).encodeABI()
            // firstData = atomicizerc.methods.atomicize(
            //   [erc721.address],
            //   [0],
            //   [(firstData.length - 2) / 2],
            //   firstData
            // ).encodeABI()

            let secondData = erc721c.methods.transferFrom(accounts[1], accounts[0], 1).encodeABI()
            // secondData = atomicizerc.methods.atomicize(
            //   [erc721.address],
            //   [0],
            //   [(secondData.length - 2) / 2],
            //   secondData
            // ).encodeABI()

            const firstCall = {target: erc721.address, howToCall: 0, data: firstData}
            const secondCall = {target: erc721.address, howToCall: 0, data: secondData}
            const sigOne = {v: 27, r: ZERO_BYTES32, s: ZERO_BYTES32}
            return exchange.sign(two, accounts[1]).then(sigTwo => {
              // return exchange.sign(one, accounts[0]).then(sigOne => {
              return exchange.atomicMatch(one, sigOne, firstCall, two, sigTwo, secondCall, ZERO_BYTES32).then(() => {
                // return erc20.balanceOf(accounts[1]).then(balance => {
                //   assert.equal(2, balance, 'Incorrect balance')
                // })
              })
              // })
            })
          })
      })
  })

  it('should match nft-nft order', () => {
    return withContracts()
      .then(({atomicizer, exchange, registry, statici, erc20, erc721}) => {
        return withSomeTokens()
          .then(({tokens, nfts}) => {
            const atomicizerc = new web3.eth.Contract(atomicizer.abi, atomicizer.address)
            const erc20c = new web3.eth.Contract(erc20.abi, erc20.address)
            const erc721c = new web3.eth.Contract(erc721.abi, erc721.address)
            const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
            const one = {registry: registry.address, maker: accounts[0], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '10000000000', salt: '2'}
            const two = {registry: registry.address, maker: accounts[0], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '10000000000', salt: '3'}
            const sig = {v: 27, r: ZERO_BYTES32, s: ZERO_BYTES32}
            const firstERC20Call = erc20c.methods.transferFrom(accounts[0], accounts[1], 2).encodeABI()
            const firstERC721Call = erc721c.methods.transferFrom(accounts[0], accounts[1], nfts[0]).encodeABI()
            const firstData = atomicizerc.methods.atomicize(
              [erc20.address, erc721.address],
              [0, 0],
              [(firstERC20Call.length - 2) / 2, (firstERC721Call.length - 2) / 2],
              firstERC20Call + firstERC721Call.slice(2)
            ).encodeABI()
            const secondERC20Call = erc20c.methods.transferFrom(accounts[0], accounts[2], 2).encodeABI()
            const secondERC721Call = erc721c.methods.transferFrom(accounts[0], accounts[2], nfts[1]).encodeABI()
            const secondData = atomicizerc.methods.atomicize(
              [erc721.address, erc20.address],
              [0, 0],
              [(secondERC721Call.length - 2) / 2, (secondERC20Call.length - 2) / 2],
              secondERC721Call + secondERC20Call.slice(2)
            ).encodeABI()
            const firstCall = {target: atomicizer.address, howToCall: 1, data: firstData}
            const secondCall = {target: atomicizer.address, howToCall: 1, data: secondData}
            return exchange.atomicMatch(one, sig, firstCall, two, sig, secondCall, ZERO_BYTES32).then(() => {
              return erc20.balanceOf(accounts[1]).then(balance => {
                assert.equal(2, balance, 'Incorrect balance')
              })
            })
          })
      })
  })

  it('should match with signatures', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const two = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        return exchange.sign(one, accounts[6]).then(oneSig => {
          return exchange.sign(two, accounts[6]).then(twoSig => {
            const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
            return exchange.atomicMatch(one, oneSig, call, two, twoSig, call, ZERO_BYTES32).then(() => {
            })
          })
        })
      })
  })

  it('should match with approvals', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const two = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        return exchange.approveOrder(one, false, {from: accounts[6]}).then(() => {
          return exchange.approveOrder(two, false, {from: accounts[6]}).then(() => {
            const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
            return exchange.atomicMatch(one, nullSig, call, two, nullSig, call, ZERO_BYTES32).then(() => {
            })
          })
        })
      })
  })

  it('should not match with invalid first order auth', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const two = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        return exchange.sign(one, accounts[6]).then(sig => {
          const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
          return exchange.atomicMatch(one, nullSig, call, two, sig, call, ZERO_BYTES32).then(() => {
            assert.equal(true, false, 'should not have matched')
          }).catch(err => {
            assert.equal(err.message, 'Returned error: VM Exception while processing transaction: revert', 'Incorrect error')
          })
        })
      })
  })

  it('should not match with invalid second order auth', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const two = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        return exchange.sign(two, accounts[6]).then(sig => {
          const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
          return exchange.atomicMatch(one, sig, call, two, nullSig, call, ZERO_BYTES32).then(() => {
            assert.equal(true, false, 'should not have matched')
          }).catch(err => {
            assert.equal(err.message, 'Returned error: VM Exception while processing transaction: revert', 'Incorrect error')
          })
        })
      })
  })

  it('should not match with invalid first order params', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const two = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        return exchange.inst.setOrderFill_(hashOrder(one), '10', {from: accounts[6]}).then(() => {
          return exchange.sign(one, accounts[6]).then(oneSig => {
            return exchange.sign(two, accounts[6]).then(twoSig => {
              const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
              return exchange.atomicMatch(one, oneSig, call, two, twoSig, call, ZERO_BYTES32).then(() => {
                assert.equal(true, false, 'should not have matched')
              }).catch(err => {
                assert.equal(err.message, 'Returned error: VM Exception while processing transaction: revert', 'Incorrect error')
              })
            })
          })
        })
      })
  })

  it('should not match with invalid second order params', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const two = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        return exchange.inst.setOrderFill_(hashOrder(two), '3', {from: accounts[6]}).then(() => {
          return exchange.sign(one, accounts[6]).then(oneSig => {
            return exchange.sign(two, accounts[6]).then(twoSig => {
              const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
              return exchange.atomicMatch(one, oneSig, call, two, twoSig, call, ZERO_BYTES32).then(() => {
                assert.equal(true, false, 'should not have matched')
              }).catch(err => {
                assert.equal(err.message, 'Returned error: VM Exception while processing transaction: revert', 'Incorrect error')
              })
            })
          })
        })
      })
  })

  it('should not match with nonexistent first proxy', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[7], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const two = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        return exchange.sign(one, accounts[7]).then(oneSig => {
          return exchange.sign(two, accounts[6]).then(twoSig => {
            const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
            return exchange.atomicMatch(one, oneSig, call, two, twoSig, call, ZERO_BYTES32).then(() => {
              assert.equal(true, false, 'should not have matched')
            }).catch(err => {
              assert.equal(err.message, 'Returned error: VM Exception while processing transaction: revert', 'Incorrect error')
            })
          })
        })
      })
  })

  it('should not match with nonexistent second proxy', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const two = {registry: registry.address, maker: accounts[7], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        return exchange.sign(one, accounts[6]).then(oneSig => {
          return exchange.sign(two, accounts[7]).then(twoSig => {
            const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
            return exchange.atomicMatch(one, oneSig, call, two, twoSig, call, ZERO_BYTES32).then(() => {
              assert.equal(true, false, 'should not have matched')
            }).catch(err => {
              assert.equal(err.message, 'Returned error: VM Exception while processing transaction: revert', 'Incorrect error')
            })
          })
        })
      })
  })

  it('should not match with nonexistent target', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const two = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        return exchange.sign(one, accounts[6]).then(oneSig => {
          return exchange.sign(two, accounts[6]).then(twoSig => {
            const call = {target: accounts[7], howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
            return exchange.atomicMatch(one, oneSig, call, two, twoSig, call, ZERO_BYTES32).then(() => {
              assert.equal(true, false, 'should not have matched')
            }).catch(err => {
              assert.equal(err.message, 'Returned error: VM Exception while processing transaction: revert', 'Incorrect error')
            })
          })
        })
      })
  })

  it('should allow value transfer', () => {
    return withContracts()
      .then(({exchange, registry, statici}) => {
        const extradata = web3.eth.abi.encodeFunctionSignature('any(address[7],uint8[2],uint256[6],bytes,bytes)')
        const one = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        const two = {registry: registry.address, maker: accounts[6], staticTarget: statici.address, staticExtradata: extradata, maximumFill: '1', listingTime: '0', expirationTime: '100000000000', salt: randomUint()}
        return exchange.sign(one, accounts[6]).then(oneSig => {
          return exchange.sign(two, accounts[6]).then(twoSig => {
            const call = {target: statici.address, howToCall: 0, data: web3.eth.abi.encodeFunctionSignature('test()')}
            return exchange.atomicMatchWith(one, oneSig, call, two, twoSig, call, ZERO_BYTES32, {value: 200}).then(() => {
            })
          })
        })
      })
  })
})
