import argparse
import os
import sys
import math
import pdb
from PIL import Image
from attacksurfacemeter.call_graph import CallGraph
from attacksurfacemeter.granularity import Granularity
from attacksurfacemeter.loaders.cflow_loader import CflowLoader
from attacksurfacemeter.loaders.gprof_loader import GprofLoader
from attacksurfacemeter.loaders.multigprof_loader import MultigprofLoader
from attacksurfacemeter.loaders.javacg_loader import JavaCGLoader
from attacksurfacemeter.formatters.txt_formatter import TxtFormatter
from attacksurfacemeter.formatters.xml_formatter import XmlFormatter
from attacksurfacemeter.formatters.html_formatter import HtmlFormatter
import matplotlib.pyplot as plt
from networkx.readwrite import json_graph
import networkx as nx
import hashlib
import random
import json

FORMATTERS = {
    'txt': TxtFormatter, 'xml': XmlFormatter, 'html': HtmlFormatter
}


def main():
    args = parse_args()

    call_graph = None
    if args.javacg:
        loader = JavaCGLoader(
            args.javacg, args.apppackages
        )
        call_graph = CallGraph.from_loader(loader)
    else:
        cflow_loader = None
        gprof_loader = None
        if args.cflow:
            if not os.path.exists(args.cflow):
                raise Exception('{} not found.'.format(args.cflow))
            else:
                cflow_loader = CflowLoader(args.cflow, reverse=args.reverse)

        if args.gprof:
            if not os.path.exists(args.gprof):
                raise Exception('{} not found.'.format(args.gprof))
            else:
                if os.path.isdir(args.gprof):
                    sources = [
                        os.path.join(args.gprof, filename)
                        for filename in os.listdir(args.gprof)
                        if os.path.isfile(os.path.join(args.gprof, filename))
                    ]
                    gprof_loader = MultigprofLoader(
                        sources, processes=args.processes
                    )
                else:
                    gprof_loader = GprofLoader(
                        args.gprof
                    )

        if cflow_loader and gprof_loader:
            call_graph = CallGraph.from_merge(
                CallGraph.from_loader(
                    cflow_loader, granularity=args.granularity
                ),
                CallGraph.from_loader(
                    gprof_loader, granularity=args.granularity
                )
            )
        elif cflow_loader:
            call_graph = CallGraph.from_loader(
                    cflow_loader, granularity=args.granularity
                )
            """nodes = []
            for curnode in call_graph.call_graph.nodes():
                    if curnode._function_signature in nodes:
                        nodes[curnode._function_signature].append(curnode)
                    else:
                        nodes[curnode._function_signature] = [curnode]"""
            plt.figure(num=None, figsize=(150, 150), dpi=100)
            critical_graph = call_graph.get_critical_graph()

            """data = json_graph.node_link_data(cg)
            e = json.dumps(data)
            print(e)
            H = json_graph.node_link_graph(data,directed=True)"""
            """"for nodekey in nodes:
                random.seed(nodekey)
                nlist = nodes[nodekey]
                col = float.fromhex('0.' + hashlib.md5(nodekey).hexdigest())
                nx.draw_networkx_nodes(cg,size=600, pos=nx.spring_layout(cg),
                                       nodelist=nlist, node_color=[random.random(),random.random(),random.random()])
            nx.draw_networkx_edges(cg,pos=nx.spring_layout(cg),edgelist=cg.edges())
            nx.draw_networkx_labels(cg,pos=nx.spring_layout(cg))"""
            #.draw(cg)

            pos = nx.spring_layout(critical_graph)
            draw_nodes(call_graph, critical_graph, pos)
            draw_edges(critical_graph, pos)
            draw_labels(critical_graph, pos)

            plt.show()
            #for inp in call_graph.entry_points:
            #    nx.draw_networkx_edges(cg,pos=nx.spring_layout,edgelist=[()])
            #plt.savefig('gtest.png')
            #plt.show()
            #plt.clf()
            #img = Image.open('gtest.png')
            #img.show()

            print("drew graph")

        elif gprof_loader:
            call_graph = CallGraph.from_loader(
                    gprof_loader, granularity=args.granularity
                )

    if args.output:
        (name, extension) = os.path.splitext(args.output)
        output_format = extension.replace('.', '')
        if output_format not in FORMATTERS:
            output_format = 'txt'
        formatter = FORMATTERS[output_format](call_graph)
        with open(args.output, 'w') as file_:
            if args.verbose:
                file_.write(formatter.write_output())
            else:
                file_.write(formatter.write_summary())
    else:
        formatter = FORMATTERS['txt'](call_graph)
        if args.verbose:
            sys.stdout.write(formatter.write_output())
        else:
            sys.stdout.write(formatter.write_summary())

    if args.showerrors and call_graph.load_errors:
        sys.stdout.write('Parse Errors\n')
        sys.stdout.write('============\n')
        for error in call_graph.load_errors:
            sys.stdout.write(error)


def draw_nodes(call_graph, critical_graph, pos):

    node_colors = []
    for node in critical_graph.nodes():
        if (node in call_graph.entry_points) and (node in call_graph.exit_points):
            if node.is_dangerous:
                node_colors.append('brown')
            else:
                node_colors.append('red')
        elif node in call_graph.exit_points:
            if node.is_dangerous:
                node_colors.append('orange')
            else:
                node_colors.append('yellow')
        elif node in call_graph.entry_points:
            if node.is_dangerous:
                node_colors.append('green')
            else:
                node_colors.append('blue')
        else:
            node_colors.append('grey')

    nx.draw_networkx_nodes(critical_graph, pos=pos, scale=8, node_size=[600], node_color=node_colors)


def draw_edges(critical_graph, pos):
    nx.draw_networkx_edges(critical_graph, pos=pos, edge_color=['grey' for edge in critical_graph.edges()])


def draw_labels(critical_graph, pos):
    labels = {}
    node_id = 0
    for node in critical_graph:
        labels[node] = node_id
        print("{0}: {1}".format(node_id, node.identity))
        node_id += 1

    nx.draw_networkx_labels(critical_graph, pos=pos, labels=labels, font_size=12)


def parse_args():
    '''Parse command line arguments.

    Parameers
    ----------
    None

    Returns
    -------
    args : object
        An object containing the command line arguments are attributes.
    '''
    parser = argparse.ArgumentParser(
        description=(
            'Collect attack surface metrics from the call graph '
            ' representation of a software system.'
        )
    )
    parser.add_argument(
        '-gr', dest='granularity', default=Granularity.FUNC,
        choices=[Granularity.FUNC, Granularity.FILE],
        help=(
            'The granularity at which the call graphs must be processed at.'
        )
    )
    parser.add_argument(
        '-c', dest='cflow',
        help=(
            'Absolute path of the file containing the textual representation '
            'of the call graph generated by GNU cflow or of the directory '
            'containing the source code of the software system to be analyzed.'
        )
    )
    parser.add_argument(
        '--reverse', action='store_true',
        help='cflow call graph was generated with the -r option.'
    )
    parser.add_argument(
        '-g', dest='gprof',
        help=(
            'Absolute path of the file containing the textual representation '
            'of the call graph generated by GNU gprof or of a directory '
            'containing multiple such text files.'
        )
    )
    parser.add_argument(
        '-p', dest='processes', type=int, default=2,
        help=(
            'Number of processes to spawn when loaded multiple gprof call '
            'graph files. Default is 2.'
        )
    )
    parser.add_argument(
        '-j', dest='javacg',
        help=(
            'Absolute path of the file containing the textual representation '
            'of the call graph generated by java-callgraph.'
        )
    )
    parser.add_argument(
        '-a', dest='apppackages', metavar='P', nargs='*',
        help=(
            'When using java-callgraph for call graph generation of android '
            'apps, specify the fully qualified package name of the method '
            'calls that will be included in the call graph. This is generally '
            'the name of the java package inside which the app\'s classes are '
            'defined.'
        )
    )
    parser.add_argument(
        '--output',
        help=(
            'Absolute path of the file to which the output should be written '
            'to. The format of output is inferred from the file extension. '
            'txt, html, and xml are currently supported. In cases when the '
            'output format cannot be inferred, txt is used. When an output '
            'path is not specified, standard output is used.'
        )
    )
    parser.add_argument(
        '--verbose', action='store_true',
        help=(
            'Output itemized report including metric values collected for '
            'each function/file.'
        )
    )
    parser.add_argument(
        '--showerrors', action='store_true',
        help='Display errors encountered when parsing call graph (if any).'
    )

    return parser.parse_args()


if __name__ == '__main__':
    main()
