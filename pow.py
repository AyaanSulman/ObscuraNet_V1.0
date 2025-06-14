import hashlib
import string
import random
import logging

logger = logging.getLogger(__name__)


def generate_pow_challenge(difficulty=4):
    """
    Generate a random 16‐char alphanumeric challenge plus a difficulty.
    Returns (challenge_str, difficulty_int).
    """
    logger.debug(f"[pow/generate_pow_challenge] Entry: difficulty={difficulty}")
    chars = string.ascii_letters + string.digits
    challenge = "".join(random.choices(chars, k=16))
    logger.info(f"[pow/generate_pow_challenge] Challenge generated: {challenge}")
    return (challenge, difficulty)


def solve_pow(challenge, difficulty):
    """
    Brute‐force a decimal nonce so that sha256(challenge+nonce).startswith('0'*difficulty).
    Returns nonce as str if found, else "-1".
    """
    logger.debug(f"[pow/solve_pow] Entry: challenge={challenge[:10]}…, difficulty={difficulty}")
    target = "0" * difficulty
    for i in range(10_000_000):
        test = challenge + str(i)
        h = hashlib.sha256(test.encode()).hexdigest()
        if h.startswith(target):
            logger.info(f"[pow/solve_pow] Found solution: nonce={i}")
            return str(i)
        if i % 1000000 == 0:
            logger.debug(f"[pow/solve_pow] Still searching at i={i}")
    logger.warning(f"[pow/solve_pow] No solution found within 10^7 tries")
    return "-1"


def verify_pow_solution(challenge, difficulty, solution):
    """
    Verify that sha256(challenge+solution).startswith('0'*difficulty).
    """
    logger.debug(f"[pow/verify_pow_solution] Entry: challenge={challenge[:10]}…, solution={solution}, difficulty={difficulty}")
    try:
        h = hashlib.sha256((challenge + solution).encode()).hexdigest()
        ok = h.startswith("0" * difficulty)
        logger.info(f"[pow/verify_pow_solution] Verification result: {ok}")
        return ok
    except Exception as e:
        logger.error(f"[pow/verify_pow_solution] Failed: {e}")
        return False
