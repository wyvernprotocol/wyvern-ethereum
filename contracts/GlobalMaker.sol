/*

  << Global Maker >>

*/

pragma solidity 0.7.5;

import "./lib/EIP1271Mod.sol";
import "./lib/ArrayUtils.sol";
import "./registry/ProxyRegistry.sol";

/**
 * @title GlobalMaker
 * @author Wyvern Protocol Developers
 */
contract GlobalMaker is ERC1271Mod {

    bytes4 constant internal SIGINVALID = 0x00000000;

    string public constant name = "Global Maker";

    /**
     * Construct a new GlobalMaker, creating the proxy it will require
     */
    constructor (ProxyRegistry registry) public {
        registry.registerProxy();
    }

    /** 
     * Check if a signature is valid
     *
     * @param _data Data signed over
     * @param _signature Encoded signature
     * @return magicValue Magic value if valid, zero-value otherwise
     */
    function isValidSignature(
        bytes memory _data,
        bytes memory _signature,
        bytes memory _extradata)
        override
        public
        view
        returns (bytes4 magicValue)
    {
        // assert signature
        bytes memory sig = ArrayUtils.arrayTake(abi.encodeWithSignature("transferFrom(address,address,uint256)"), 4);
        require(ArrayUtils.arrayEq(sig, ArrayUtils.arrayTake(_extradata, 4)));

        // decode calldata
        (address callFrom, address callTo, uint256 token) = abi.decode(ArrayUtils.arrayDrop(_extradata, 4), (address, address, uint256));

        // check that the user (whoever is sending the tokens) signed the order hash
        bytes32 hash = abi.decode(_data, (bytes32));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(_signature, (uint8, bytes32, bytes32));
        if (callFrom == ecrecover(hash, v, r, s)) {
            return MAGICVALUE;
        } else {
            return SIGINVALID;
        }   
    }   

}
