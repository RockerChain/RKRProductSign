pragma solidity ^0.4.18;

import "../node_modules/openzeppelin-solidity/contracts/ownership/Ownable.sol";

contract RKRProductSign is Ownable{
    
    //archive of digital sign, every product is associated with a signed archive 
    mapping(bytes32 => bytes32) digitalCertificateArchive;

    function Sign(string guid, string hash) public onlyWhitelisted {
        
        bytes32 hashed = keccak256(abi.encodePacked(guid));
        bytes32 hashedSign = keccak256(abi.encodePacked(hash)); 
        digitalCertificateArchive[hashed] = hashedSign;
    }

    function CheckSign(string guid, string hash) public view returns(bool){
        bytes32 hashed = keccak256(abi.encodePacked(guid));
        bytes32 hashedSign = keccak256(abi.encodePacked(hash)); 
        return digitalCertificateArchive[hashed] == hashedSign;
    }



  mapping (address => bool) whitelist;

  event WhitelistedAddressAdded(address addr);
  event WhitelistedAddressRemoved(address addr);

  /**
   * @dev Throws if called by any account that's not whitelisted.
   */
  modifier onlyWhitelisted() {
    whitelist[msg.sender] == true;
    _;
  }

  /**
   * @dev add an address to the whitelist
   * @param addr address
   * @return true if the address was added to the whitelist, false if the address was already in the whitelist
   */
  function addAddressToWhitelist(address addr)
    onlyOwner
    public
  {
    whitelist[addr] = true;
    emit WhitelistedAddressAdded(addr);
  }

  /**
   * @dev getter to determine if address is in whitelist
   */
  function isInWhitelist(address addr)
    public
    view
    returns (bool)
  {
    return whitelist[addr] == true;
  }

  /**
   * @dev add addresses to the whitelist
   * @param addrs addresses
   * @return true if at least one address was added to the whitelist,
   * false if all addresses were already in the whitelist
   */
  function addAddressesToWhitelist(address[] addrs)
    onlyOwner
    public
  {
    for (uint256 i = 0; i < addrs.length; i++) {
      addAddressToWhitelist(addrs[i]);
    }
  }

  /**
   * @dev remove an address from the whitelist
   * @param addr address
   * @return true if the address was removed from the whitelist,
   * false if the address wasn't in the whitelist in the first place
   */
  function removeAddressFromWhitelist(address addr)
    onlyOwner
    public
  {
    whitelist[addr] = false;
    emit WhitelistedAddressRemoved(addr);
  }

  /**
   * @dev remove addresses from the whitelist
   * @param addrs addresses
   * @return true if at least one address was removed from the whitelist,
   * false if all addresses weren't in the whitelist in the first place
   */
  function removeAddressesFromWhitelist(address[] addrs)
    onlyOwner
    public
  {
    for (uint256 i = 0; i < addrs.length; i++) {
      removeAddressFromWhitelist(addrs[i]);
    }
  }
}