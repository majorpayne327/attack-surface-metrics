__author__ = 'kevin'

import subprocess
import os
import networkx as nx

from attacksurfacemeter import Stack
from attacksurfacemeter import Call


class CflowLoader():
    """"""

    def __init__(self, source, reverse=False):
        """Constructor for CflowParser"""
        self.source = source
        self.is_reverse = reverse

    def load_call_graph(self):
        """
            Generates the Call Graph as a networkx.DiGraph object.

            Invokes the call grap generation software (cflow) and creates a networkx.DiGraph instance that represents
            the analyzed source code's Call Graph.

            Args:
                is_reverse: Boolean specifying whether the graph generation software (cflow) should use the reverse
                    algorithm.

            Returns:
                None
        """
        call_graph = nx.DiGraph()
        is_first_line = True
        parent = Stack()

        if os.path.isfile(self.source):
            raw_call_graph = open(self.source)
            readline = lambda: raw_call_graph.readline()

        elif os.path.isdir(self.source):
            raw_call_graph = self._exec_cflow(self.is_reverse)
            readline = lambda: raw_call_graph.stdout.readline().decode(encoding='UTF-8')

        while True:
            line = readline()

            if line == '':
                break

            current = Call(line)

            if not is_first_line:
                if current.level > previous.level:
                    parent.push(previous)
                elif current.level < previous.level:
                    for t in range(previous.level - current.level):
                        parent.pop()

                if parent.top:
                    if not self.is_reverse:
                        call_graph.add_edge(parent.top, current)
                    else:
                        call_graph.add_edge(current, parent.top)

            previous = current
            is_first_line = False

        return call_graph

    def _exec_cflow(self, is_reverse):
        """
            Creates a subprocess.Popen instance representing the cflow call.

            Args:
                is_reverse: Boolean specifying whether the graph generation software (cflow) should use the reverse
                    algorithm.

            Returns:
                A subprocess.Popen instance representing the cflow call.
        """
        if is_reverse:
            cflow_exe = 'run_cflow_r.sh'
        else:
            cflow_exe = 'run_cflow.sh'

        dirname = os.path.dirname(os.path.realpath(__file__))
        proc = subprocess.Popen(['sh', os.path.join(dirname, cflow_exe), self.source],
                                stdout=subprocess.PIPE)

        return proc