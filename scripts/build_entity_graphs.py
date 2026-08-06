import argparse
from pathlib import Path
def main():
    p=argparse.ArgumentParser(); p.add_argument('--output',required=True); args=p.parse_args(); Path(args.output).write_text('{"status":"contract_only"}\n',encoding='utf-8')
if __name__ == '__main__': main()
