pragma solidity ^0.6.6;
import "@openzeppelin/contracts/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@nomiclabs/buidler/console.sol";

contract Peggy {
	using SafeMath for uint256;

	// These are updated often
	bytes32 public state_lastCheckpoint;
	uint256 public state_lastTxNonce = 0;

	// These are set once at initialization
	address public state_tokenContract;
	bytes32 public state_peggyId;
	uint256 public state_powerThreshold;

	event ValsetUpdatedEvent(address[] _validators, uint256[] _powers);
	event TransferOutEvent(bytes32 _destination, uint256 _amount);

	// TEST FIXTURES
	// These are here to make it easier to measure gas usage. They should be removed before production
	function testMakeCheckpoint(
		address[] memory _validators,
		uint256[] memory _powers,
		uint256 _valsetNonce,
		bytes32 _peggyId
	) public {
		makeCheckpoint(_validators, _powers, _valsetNonce, _peggyId);
	}

	function testCheckValidatorSignatures(
		address[] memory _currentValidators,
		uint256[] memory _currentPowers,
		uint8[] memory _v,
		bytes32[] memory _r,
		bytes32[] memory _s,
		bytes32 _theHash,
		uint256 _powerThreshold
	) public {
		checkValidatorSignatures(
			_currentValidators,
			_currentPowers,
			_v,
			_r,
			_s,
			_theHash,
			_powerThreshold
		);
	}

	// END TEST FIXTURES

	// Utility function to verify geth style signatures
	function verifySig(
		address _signer,
		bytes32 _theHash,
		uint8 _v,
		bytes32 _r,
		bytes32 _s
	) private pure returns (bool) {
		bytes32 messageDigest = keccak256(
			abi.encodePacked("\x19Ethereum Signed Message:\n32", _theHash)
		);
		return _signer == ecrecover(messageDigest, _v, _r, _s);
	}

	// Make a new checkpoint from the supplied validator set
	// A checkpoint is a hash of all relevant information about the valset. This is stored by the contract,
	// instead of storing the information directly. This saves on storage and gas.
	// The format of the checkpoint is:
	// h(peggyId, "checkpoint", valsetNonce, validators[], powers[])
	// Where h is the keccak256 hash function.
	// The validator powers must be decreasing or equal. This is important for checking the signatures on the
	// next valset, since it allows the caller to stop verifying signatures once a quorum of signatures have been verified.
	function makeCheckpoint(
		address[] memory _validators,
		uint256[] memory _powers,
		uint256 _valsetNonce,
		bytes32 _peggyId
	) public pure returns (bytes32) {
		// bytes32 encoding of the string "checkpoint"
		bytes32 methodName = 0x636865636b706f696e7400000000000000000000000000000000000000000000;

		bytes32 checkpoint = keccak256(
			abi.encode(_peggyId, methodName, _valsetNonce, _validators, _powers)
		);

		return checkpoint;
	}

	function checkValidatorSignatures(
		// The current validator set and their powers
		address[] memory _currentValidators,
		uint256[] memory _currentPowers,
		// The current validator's signatures
		uint8[] memory _v,
		bytes32[] memory _r,
		bytes32[] memory _s,
		// This is what we are checking they have signed
		bytes32 _theHash,
		uint256 _powerThreshold
	) public pure {
		uint256 cumulativePower = 0;

		for (uint256 k = 0; k < _currentValidators.length; k = k.add(1)) {
			// If v is set to 0, this signifies that it was not possible to get a signature from this validator and we skip evaluation
			// (In a valid signature, it is either 27 or 28)
			if (_v[k] != 0) {
				// Check that the current validator has signed off on the hash
				require(
					verifySig(_currentValidators[k], _theHash, _v[k], _r[k], _s[k]),
					"Validator signature does not match."
				);

				// Sum up cumulative power
				cumulativePower = cumulativePower + _currentPowers[k];

				// Break early to avoid wasting gas
				if (cumulativePower > _powerThreshold) {
					break;
				}
			}
		}

		// Check that there was enough power
		require(
			cumulativePower > _powerThreshold,
			"Submitted validator set signatures do not have enough power."
		);
	}

	// This updates the valset by checking that the validators in the current valset have signed off on the
	// new valset. The signatures supplied are the signatures of the current valset over the checkpoint hash
	// generated from the new valset.
	function updateValset(
		// The new version of the validator set
		address[] memory _newValidators,
		uint256[] memory _newPowers,
		uint256 _newValsetNonce,
		// The current validators that approve the change
		address[] memory _currentValidators,
		uint256[] memory _currentPowers,
		uint256 _currentValsetNonce,
		// These are arrays of the parts of the current validator's signatures
		uint8[] memory _v,
		bytes32[] memory _r,
		bytes32[] memory _s
	) public {
		// CHECKS

		// Check that new validators and powers set is well-formed
		require(_newValidators.length == _newPowers.length, "Malformed new validator set");

		// Check that current validators, powers, and signatures (v,r,s) set is well-formed
		require(
			_currentValidators.length == _currentPowers.length &&
				_currentValidators.length == _v.length &&
				_currentValidators.length == _r.length &&
				_currentValidators.length == _s.length,
			"Malformed current validator set"
		);

		// Check that the supplied current validator set matches the saved checkpoint
		require(
			makeCheckpoint(
				_currentValidators,
				_currentPowers,
				_currentValsetNonce,
				state_peggyId
			) == state_lastCheckpoint,
			"Supplied current validators and powers do not match checkpoint."
		);

		// Check that the valset nonce is greater than the old one
		require(
			_newValsetNonce > _currentValsetNonce,
			"New valset nonce must be greater than the current nonce"
		);

		// Check that enough current validators have signed off on the new validator set
		bytes32 newCheckpoint = makeCheckpoint(
			_newValidators,
			_newPowers,
			_newValsetNonce,
			state_peggyId
		);

		checkValidatorSignatures(
			_currentValidators,
			_currentPowers,
			_v,
			_r,
			_s,
			newCheckpoint,
			state_powerThreshold
		);

		// ACTIONS

		// Stored to be used next time to validate that the valset
		// supplied by the caller is correct.
		state_lastCheckpoint = newCheckpoint;

		// LOGS

		emit ValsetUpdatedEvent(_newValidators, _newPowers);
	}

	// This function submits a batch of transactions to be executed on Ethereum.
	// The caller must supply the current validator set, along with their signatures over the batch.
	// The contract checks that this validator set matches the saved checkpoint, then verifies their
	// signatures over a hash of the tx batch.
	function submitBatch(
		// The validators that approve the batch
		address[] memory _currentValidators,
		uint256[] memory _currentPowers,
		uint256 _currentValsetNonce,
		// These are arrays of the parts of the validators signatures
		uint8[] memory _v,
		bytes32[] memory _r,
		bytes32[] memory _s,
		// The batch of transactions
		uint256[] memory _amounts,
		address[] memory _destinations,
		uint256[] memory _fees,
		uint256[] memory _nonces // TODO: multi-erc20 support (input contract address).
	) public {
		// CHECKS

		// Check that current validators, powers, and signatures (v,r,s) set is well-formed
		require(
			_currentValidators.length == _currentPowers.length &&
				_currentValidators.length == _v.length &&
				_currentValidators.length == _r.length &&
				_currentValidators.length == _s.length,
			"Malformed current validator set"
		);

		// Check that the transaction batch is well-formed
		require(
			_amounts.length == _destinations.length &&
				_amounts.length == _fees.length &&
				_amounts.length == _nonces.length,
			"Malformed batch of transactions"
		);

		// Check that the supplied current validator set matches the saved checkpoint
		require(
			makeCheckpoint(
				_currentValidators,
				_currentPowers,
				_currentValsetNonce,
				state_peggyId
			) == state_lastCheckpoint,
			"Supplied current validators and powers do not match checkpoint."
		);

		// Check that the tx nonces are higher than the stored nonce and are
		// strictly increasing (can have gaps)
		uint256 lastTxNonceTemp = state_lastTxNonce;
		{
			for (uint256 i = 0; i < _nonces.length; i = i.add(1)) {
				require(
					_nonces[i] > lastTxNonceTemp,
					"Transaction nonces in batch must be higher than last transaction nonce and strictly increasing"
				);

				lastTxNonceTemp = _nonces[i];
			}
		}

		// bytes32 encoding of "transactionBatch"
		bytes32 methodName = 0x7472616e73616374696f6e426174636800000000000000000000000000000000;

		// Get hash of the transaction batch
		bytes32 transactionsHash = keccak256(
			abi.encode(state_peggyId, methodName, _amounts, _destinations, _fees, _nonces)
		);

		// Check that enough current validators have signed off on the transaction batch
		checkValidatorSignatures(
			_currentValidators,
			_currentPowers,
			_v,
			_r,
			_s,
			transactionsHash,
			state_powerThreshold
		);

		// ACTIONS

		// Store nonce
		state_lastTxNonce = lastTxNonceTemp;

		// Send transaction amounts to destinations
		// Send transaction fees to msg.sender
		uint256 totalFee;
		{
			for (uint256 i = 0; i < _amounts.length; i = i.add(1)) {
				IERC20(state_tokenContract).transfer(_destinations[i], _amounts[i]);
				totalFee = totalFee.add(_fees[i]);
			}
			IERC20(state_tokenContract).transfer(msg.sender, totalFee);
		}
	}

	function updateValsetAndSubmitBatch(
		// The validators that approve the batch and new valset
		address[] memory _currentValidators,
		uint256[] memory _currentPowers,
		uint256 _currentValsetNonce,
		// These are arrays of the parts of the validators signatures
		uint8[] memory _v,
		bytes32[] memory _r,
		bytes32[] memory _s,
		// The new version of the validator set
		address[] memory _newValidators,
		uint256[] memory _newPowers,
		uint256 _newValsetNonce,
		// The batch of transactions
		uint256[] memory _amounts,
		address[] memory _destinations,
		uint256[] memory _fees,
		uint256[] memory _nonces // TODO: multi-erc20 support (input contract address).)
	) public {
		// CHECKS

		// Check that current validators, powers, and signatures (v,r,s) set is well-formed
		require(
			_currentValidators.length == _currentPowers.length &&
				_currentValidators.length == _v.length &&
				_currentValidators.length == _r.length &&
				_currentValidators.length == _s.length,
			"Malformed current validator set"
		);

		// Check that new validators and powers set is well-formed
		require(_newValidators.length == _newPowers.length, "Malformed new validator set");

		// Check that the valset nonce is greater than the old one
		require(
			_newValsetNonce > _currentValsetNonce,
			"New valset nonce must be greater than the current nonce"
		);

		// Check that the transaction batch is well-formed
		require(
			_amounts.length == _destinations.length &&
				_amounts.length == _fees.length &&
				_amounts.length == _nonces.length,
			"Malformed batch of transactions"
		);

		// Check that the supplied current validator set matches the saved checkpoint
		require(
			makeCheckpoint(
				_currentValidators,
				_currentPowers,
				_currentValsetNonce,
				state_peggyId
			) == state_lastCheckpoint,
			"Supplied current validators and powers do not match checkpoint."
		);

		// Check that the tx nonces are higher than the stored nonce and are
		// strictly increasing (can have gaps)
		uint256 lastTxNonceTemp = state_lastTxNonce;
		{
			for (uint256 i = 0; i < _nonces.length; i = i.add(1)) {
				require(
					_nonces[i] > lastTxNonceTemp,
					"Transaction nonces in batch must be higher than last transaction nonce and strictly increasing"
				);

				lastTxNonceTemp = _nonces[i];
			}
		}

		bytes32 newCheckpoint = makeCheckpoint(
			_newValidators,
			_newPowers,
			_newValsetNonce,
			state_peggyId
		);

		// Check that enough current validators have signed off on the transaction batch and valset
		checkValidatorSignatures(
			_currentValidators,
			_currentPowers,
			_v,
			_r,
			_s,
			// Get hash of the transaction batch and checkpoint
			keccak256(
				abi.encode(
					state_peggyId,
					// bytes32 encoding of "valsetAndTransactionBatch"
					0x76616c736574416e645472616e73616374696f6e426174636800000000000000,
					_amounts,
					_destinations,
					_fees,
					_nonces,
					newCheckpoint
				)
			),
			state_powerThreshold
		);

		// ACTIONS

		// Store nonce
		state_lastTxNonce = lastTxNonceTemp;

		// Stored to be used next time to validate that the valset
		// supplied by the caller is correct.
		state_lastCheckpoint = newCheckpoint;

		// Send transaction amounts to destinations
		// Send transaction fees to msg.sender
		{
			uint256 totalFee;
			for (uint256 i = 0; i < _amounts.length; i = i.add(1)) {
				IERC20(state_tokenContract).transfer(_destinations[i], _amounts[i]);
				totalFee = totalFee.add(_fees[i]);
			}
			IERC20(state_tokenContract).transfer(msg.sender, totalFee);
		}

		// LOGS

		emit ValsetUpdatedEvent(_newValidators, _newPowers);
	}

	function transferOut(bytes32 _destination, uint256 _amount) public {
		IERC20(state_tokenContract).transferFrom(msg.sender, address(this), _amount);
		emit TransferOutEvent(_destination, _amount);
	}

	constructor(
		// The token that this bridge bridges
		address _tokenContract,
		// A unique identifier for this peggy instance to use in signatures
		bytes32 _peggyId,
		// How much voting power is needed to approve operations
		uint256 _powerThreshold,
		// The validator set
		address[] memory _validators,
		uint256[] memory _powers,
		// These are arrays of the parts of the validators signatures
		uint8[] memory _v,
		bytes32[] memory _r,
		bytes32[] memory _s
	) public {
		// CHECKS

		// Check that validators, powers, and signatures (v,r,s) set is well-formed
		require(
			_validators.length == _powers.length &&
				_validators.length == _v.length &&
				_validators.length == _r.length &&
				_validators.length == _s.length,
			"Malformed current validator set"
		);

		bytes32 newCheckpoint = makeCheckpoint(_validators, _powers, 0, _peggyId);

		checkValidatorSignatures(
			_validators,
			_powers,
			_v,
			_r,
			_s,
			keccak256(abi.encode(newCheckpoint, _tokenContract, _peggyId, _powerThreshold)),
			_powerThreshold
		);

		// ACTIONS

		state_tokenContract = _tokenContract;
		state_peggyId = _peggyId;
		state_powerThreshold = _powerThreshold;
		state_lastCheckpoint = newCheckpoint;
	}

	// -------------------------------  BLS Signature  -------------------------------
	struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }

    // return the generator of G1
    function P1() internal returns (G1Point memory) {
        return G1Point(1, 2);
    }

    // return the generator of G2
    function P2() internal returns (G2Point memory) {
        return G2Point(
            [11559732032986387107991004021392285783925812861821192530917403151452391805634,
            10857046999023057135944570762232829481370756359578518086990519993285655852781],

            [4082367875863433681332203403145435568316851327593401208105741076214120093531,
            8495653923123431417604973247489272438418190587263600148770280649306958101930]
        );
    }

	// For comparison: example of ecrecover verification
	function testVerifyECDSA(
		address[] memory _signers,
		uint8[] memory _v,
		bytes32[] memory _r,
		bytes32[] memory _s,
		bytes32 _theHash
	) public returns (bool) {
        return verifySig(_signers[0], _theHash, _v[0], _r[0], _s[0]);
    }

	// Example of BLS signature verification
    function testVerifyBLS() public returns (bool) {

        bytes memory message = hex"7b0a2020226f70656e223a207b0a20202020227072696365223a2039353931372c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333134323430302c0a2020202020202269736f223a2022323031362d31322d33315430303a30303a30302e3030305a220a202020207d0a20207d2c0a202022636c6f7365223a207b0a20202020227072696365223a2039363736302c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333232383830302c0a2020202020202269736f223a2022323031372d30312d30315430303a30303a30302e3030305a220a202020207d0a20207d2c0a2020226c6f6f6b7570223a207b0a20202020227072696365223a2039363736302c0a20202020226b223a20312c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333232383830302c0a2020202020202269736f223a2022323031372d30312d30315430303a30303a30302e3030305a220a202020207d0a20207d0a7d0a6578616d706c652e636f6d2f6170692f31";

        G1Point memory signature = G1Point(11181692345848957662074290878138344227085597134981019040735323471731897153462, 6479746447046570360435714249272776082787932146211764251347798668447381926167);

        G2Point memory v = G2Point(
            [18523194229674161632574346342370534213928970227736813349975332190798837787897, 5725452645840548248571879966249653216818629536104756116202892528545334967238],
            [3816656720215352836236372430537606984911914992659540439626020770732736710924, 677280212051826798882467475639465784259337739185938192379192340908771705870]
        );

        G1Point memory h = hashToG1(message);

        return pairing2(negate(signature), P2(), h, v);
    }

	//Example of BGLS signature verification with 2 signers
    //Note that the messages differ in their last character.
    function testVerifyBGLS2() public returns (bool) {

        uint numberOfSigners = 2;

        G1Point memory signature = G1Point(7985250684665362734034207174567341000146996823387166378141631317099216977152, 5471024627060516972461571110176333017668072838695251726406965080926450112048);

        bytes memory message0 = hex"7b0a2020226f70656e223a207b0a20202020227072696365223a2039353931372c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333134323430302c0a2020202020202269736f223a2022323031362d31322d33315430303a30303a30302e3030305a220a202020207d0a20207d2c0a202022636c6f7365223a207b0a20202020227072696365223a2039363736302c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333232383830302c0a2020202020202269736f223a2022323031372d30312d30315430303a30303a30302e3030305a220a202020207d0a20207d2c0a2020226c6f6f6b7570223a207b0a20202020227072696365223a2039363736302c0a20202020226b223a20312c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333232383830302c0a2020202020202269736f223a2022323031372d30312d30315430303a30303a30302e3030305a220a202020207d0a20207d0a7d0a6578616d706c652e636f6d2f6170692f30";
        bytes memory message1 = hex"7b0a2020226f70656e223a207b0a20202020227072696365223a2039353931372c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333134323430302c0a2020202020202269736f223a2022323031362d31322d33315430303a30303a30302e3030305a220a202020207d0a20207d2c0a202022636c6f7365223a207b0a20202020227072696365223a2039363736302c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333232383830302c0a2020202020202269736f223a2022323031372d30312d30315430303a30303a30302e3030305a220a202020207d0a20207d2c0a2020226c6f6f6b7570223a207b0a20202020227072696365223a2039363736302c0a20202020226b223a20312c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333232383830302c0a2020202020202269736f223a2022323031372d30312d30315430303a30303a30302e3030305a220a202020207d0a20207d0a7d0a6578616d706c652e636f6d2f6170692f31";

        G2Point memory v0 = G2Point(
            [15516709285352539082439213720585739724329002971882390582209636960597958801449, 19324541677661060388134143597417835654030498723817274130329567224531700170734],
            [16550775633156536193089672538964908973667410921848053632462693002610771214528, 10154483139478025296468271477739414260393126999813603835827647034319242387010]
        );

        G2Point memory v1 = G2Point(
            [14125383697019450293340447180826714775062600193406387386692146468060627933203, 10886345395648455940547500614900453787797209052692168129177801883734751834552],
            [13494666809312056575532152175382485778895768300692817869062640713829304801648, 10580958449683540742032499469496205826101096579572266360455646078388895706251]
        );

        G1Point memory h0 = hashToG1(message0);
        G1Point memory h1 = hashToG1(message1);

        G1Point[] memory a = new G1Point[](numberOfSigners + 1);
        G2Point[] memory b = new G2Point[](numberOfSigners + 1);
        a[0] = negate(signature);
        a[1] = h0;
        a[2] = h1;
        b[0] = P2();
        b[1] = v0;
        b[2] = v1;

        return pairing(a, b);
    }

    //Example of BGLS signature verification with 3 signers
    //Note that the messages differ in their last character.
    function testVerifyBGLS3() public returns (bool) {

        uint numberOfSigners = 3;

        G1Point memory signature = G1Point(385846518441062319503502284295243290270560187383398932887791670182362540842, 19731933537428695151702009864745685458233056709189425720845387511061953267292);

        bytes memory message0 = hex"7b0a2020226f70656e223a207b0a20202020227072696365223a2039353931372c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333134323430302c0a2020202020202269736f223a2022323031362d31322d33315430303a30303a30302e3030305a220a202020207d0a20207d2c0a202022636c6f7365223a207b0a20202020227072696365223a2039363736302c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333232383830302c0a2020202020202269736f223a2022323031372d30312d30315430303a30303a30302e3030305a220a202020207d0a20207d2c0a2020226c6f6f6b7570223a207b0a20202020227072696365223a2039363736302c0a20202020226b223a20312c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333232383830302c0a2020202020202269736f223a2022323031372d30312d30315430303a30303a30302e3030305a220a202020207d0a20207d0a7d0a6578616d706c652e636f6d2f6170692f30";
        bytes memory message1 = hex"7b0a2020226f70656e223a207b0a20202020227072696365223a2039353931372c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333134323430302c0a2020202020202269736f223a2022323031362d31322d33315430303a30303a30302e3030305a220a202020207d0a20207d2c0a202022636c6f7365223a207b0a20202020227072696365223a2039363736302c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333232383830302c0a2020202020202269736f223a2022323031372d30312d30315430303a30303a30302e3030305a220a202020207d0a20207d2c0a2020226c6f6f6b7570223a207b0a20202020227072696365223a2039363736302c0a20202020226b223a20312c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333232383830302c0a2020202020202269736f223a2022323031372d30312d30315430303a30303a30302e3030305a220a202020207d0a20207d0a7d0a6578616d706c652e636f6d2f6170692f31";
        bytes memory message2 = hex"7b0a2020226f70656e223a207b0a20202020227072696365223a2039353931372c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333134323430302c0a2020202020202269736f223a2022323031362d31322d33315430303a30303a30302e3030305a220a202020207d0a20207d2c0a202022636c6f7365223a207b0a20202020227072696365223a2039363736302c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333232383830302c0a2020202020202269736f223a2022323031372d30312d30315430303a30303a30302e3030305a220a202020207d0a20207d2c0a2020226c6f6f6b7570223a207b0a20202020227072696365223a2039363736302c0a20202020226b223a20312c0a202020202274696d65223a207b0a20202020202022756e6978223a20313438333232383830302c0a2020202020202269736f223a2022323031372d30312d30315430303a30303a30302e3030305a220a202020207d0a20207d0a7d0a6578616d706c652e636f6d2f6170692f32";

        G2Point memory v0 = G2Point(
            [1787282038370667094324364195810339512415273589223814213215040505578200405366, 414568866548933554513940840943382696902163788831396286279770126458218272940],
            [6560020551439455112781785895092032589010633560844445112872109862153018855017, 19411093226570397520343120724285433000937737461010544490862811136406407315543]
        );

        G2Point memory v1 = G2Point(
            [14831125462625540363404323739936082597729714855858291605999144010730542058037, 8342129546329626371616639780890580451066604883761980695690870205390518348707],
            [808186590373043742842665711030588185456231663895663328011864547134240543671, 1856705676948889458735296604372981546875220644939188415241687241562401814459]
        );

        G2Point memory v2 = G2Point(
            [12507030828714819990408995725310388936101611986473926829733453468215798265704, 16402225253711577242710704509153100189802817297679524801952098990526969620006],
            [18717845356690477533392378472300056893077745517009561191866660997312973511514, 20124563173642533900823905467925868861151292863229012000403558815142682516349]
        );

        G1Point memory h0 = hashToG1(message0);
        G1Point memory h1 = hashToG1(message1);
        G1Point memory h2 = hashToG1(message2);

        G1Point[] memory a = new G1Point[](numberOfSigners + 1);
        G2Point[] memory b = new G2Point[](numberOfSigners + 1);
        a[0] = negate(signature);
        a[1] = h0;
        a[2] = h1;
        a[3] = h2;
        b[0] = P2();
        b[1] = v0;
        b[2] = v1;
        b[3] = v2;

        return pairing(a, b);
    }

    // return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);

        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[0];
            input[i * 6 + 3] = p2[i].X[1];
            input[i * 6 + 4] = p2[i].Y[0];
            input[i * 6 + 5] = p2[i].Y[1];
        }

        uint[1] memory out;
        bool success;

        assembly {
            success := call(sub(gas(), 2000), 8, 0, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
        // Use "invalid" to make gas estimation work
            switch success case 0 {invalid()}
        }
        require(success);
        return out[0] != 0;
    }

    /// Convenience method for a pairing check for two pairs.
    function pairing2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }

    function hashToG1(bytes memory message) internal returns (G1Point memory) {
        uint256 h = uint256(keccak256(message));
        return mul(P1(), h);
    }

    function modPow(uint256 base, uint256 exponent, uint256 modulus) internal returns (uint256) {
        uint256[6] memory input = [32, 32, 32, base, exponent, modulus];
        uint256[1] memory result;
        assembly {
            if iszero(call(not(0), 0x05, 0, input, 0xc0, result, 0x20)) {
                revert(0, 0)
            }
        }
        return result[0];
    }

    // return the negation of p, i.e. p.add(p.negate()) should be zero.
    function negate(G1Point memory p) internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }

    // return the sum of two points of G1
    function add(G1Point memory p1, G1Point memory p2) internal returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := call(sub(gas(), 2000), 6, 0, input, 0xc0, r, 0x60)
        // Use "invalid" to make gas estimation work
            switch success case 0 {invalid()}
        }
        require(success);
    }
    // return the product of a point on G1 and a scalar, i.e.
    /// p == p.mul(1) and p.add(p) == p.mul(2) for all points p.
    function mul(G1Point memory p, uint s) internal returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := call(sub(gas(), 2000), 7, 0, input, 0x80, r, 0x60)
        // Use "invalid" to make gas estimation work
            switch success case 0 {invalid()}
        }
        require(success);
    }

}