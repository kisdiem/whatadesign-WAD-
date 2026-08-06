import argparse
from pathlib import Path
def main():
    p=argparse.ArgumentParser(); p.add_argument('--output',required=True); args=p.parse_args(); Path(args.output).write_text('{"real_training_completed":false,"status":"blocked_by_data"}\n',encoding='utf-8')
if __name__ == '__main__': main()
