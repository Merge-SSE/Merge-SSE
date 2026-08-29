import argparse


def convert_io(input_file, output_file):
    with open(input_file, "r") as f_in, open(output_file, "w") as f_out:
        for line in f_in:
            values = line.split(",")
            f_out.write(f"{len(values)-1}\n")


parser = argparse.ArgumentParser(description="Convert the raw inverted index into a per-keyword response volume file.")
parser.add_argument('-n', '--n-docs', type=int, default=400000, dest='N_docs',
                     help="Number of documents the inverted index was built from (default: 400000)")
args = parser.parse_args()

N_docs = args.N_docs

input_file = f"../input/inverted_index_{N_docs}.txt"
output_file = f"../input/inverted_index_{N_docs}_io.txt"
convert_io(input_file, output_file)
