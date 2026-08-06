import argparse
def main():
    p=argparse.ArgumentParser(); p.add_argument('--sealed',required=True); p.add_argument('--labels',required=True); args=p.parse_args(); raise RuntimeError('AIT scoring is intentionally unavailable until sealed predictions and separately supplied labels exist')
if __name__ == '__main__': main()
