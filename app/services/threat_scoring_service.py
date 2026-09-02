from transformers import pipeline

# Load pipeline globally to avoid reloading on every request
try:
    phishing_classifier = pipeline(
        "text-classification", model="ElSlay/BERT-Phishing-Email-Model"
    )
except Exception as e:
    print(f"Warning: Failed to load model. Error: {e}")
    phishing_classifier = None


class ThreatScoringService:
    def __init__(self, body: str, technical_flags_score: float):
        self.body = body
        self.technical_flags_score = technical_flags_score

    def get_model_score(self) -> float:
        if not phishing_classifier or not self.body.strip():
            return 0.0

        try:
            # Truncate body if it's too long for BERT (typically 512 tokens)
            text_to_analyze = self.body[:2000]
            result = phishing_classifier(text_to_analyze)[0]

            label = result["label"].lower()
            score = result["score"]

            # Convert model output to a 0-100 maliciousness score
            if "phish" in label or "malicious" in label:
                return score * 100
            elif "safe" in label or "benign" in label:
                return (1 - score) * 100
            else:
                # Fallback if label structure is unknown
                return score * 100
        except Exception as e:
            print(f"Error during model classification: {e}")
            return 0.0

    def generate_final_score(self) -> float:
        model_score = self.get_model_score()

        # Combine model score and technical flags
        final_score = model_score + self.technical_flags_score

        # Normalize to 0-100
        return min(max(final_score, 0.0), 100.0)
