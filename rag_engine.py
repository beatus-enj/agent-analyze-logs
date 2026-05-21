class VectorDB:

    def similarity_search(self, features, k=3):
        return [
            {
                "attack_type": "Brute Force Attack",
                "resolution": [
                    "Block suspicious IP addresses",
                    "Enable MFA",
                    "Monitor failed login attempts"
                ]
            }
        ]