import _bootstrap
import argparse
from src.evaluation.protocol_gates import seal_predictions
def main():
    p=argparse.ArgumentParser(); p.add_argument('path'); p.add_argument('--output'); args=p.parse_args(); print(seal_predictions(args.path, args.output))
if __name__ == '__main__': main()
