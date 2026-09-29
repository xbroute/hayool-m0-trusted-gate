import unittest


class ControlledFailure(unittest.TestCase):
    def test_candidate_cannot_vote_away_a_real_failure(self):
        self.fail('intentional gate-repository hard failure injection')
