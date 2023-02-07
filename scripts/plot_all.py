import matplotlib.pyplot as plt
import sys
import datetime
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')

def plot_cwnd_stats(pdf_dir='', fname='', nbits='', rate='', run=''):
    df = []
    for host in [ '.hylia' ]:
        filename = fname + '_lgc_BITS_' + nbits + '_RATE_' + rate + '_RUN_' + run + '.dat' + host
        df.append(pd.read_csv(filename, header=None, sep=','))

    # Set as index the first column - Timestamps
    df[0].set_index(0, inplace=True)
    # df[1].set_index(0, inplace=True)
    # df[2].set_index(0, inplace=True)
    # df[3].set_index(0, inplace=True)
    # df[4].set_index(0, inplace=True)

    # Relative time - Start Time from 0
    df[0].index = [idx0 - df[0].index[0] for idx0 in df[0].index]
    # df[1].index = [idx1 - df[1].index[0] for idx1 in df[1].index]
    # df[2].index = [idx2 - df[2].index[0] for idx2 in df[2].index]
    # df[3].index = [idx3 - df[3].index[0] for idx3 in df[3].index]
    # df[4].index = [idx4 - df[4].index[0] for idx4 in df[4].index]

    df[0].replace(0, np.nan)
    # df[1].replace(0, np.nan)
    # df[2].replace(0, np.nan)
    # df[3].replace(0, np.nan)
    # df[4].replace(0, np.nan)

    # Plot graph
    ax = df[0].iloc[:,1].plot(linewidth=2, fontsize=20)
    # df[1].plot(linewidth=2, fontsize=20, ax=ax)
    # df[2].plot(linewidth=2, fontsize=20, ax=ax)
    # df[3].plot(linewidth=2, fontsize=20, ax=ax)
    # df[4].plot(linewidth=2, fontsize=20, ax=ax)

    # sns.set_style("ticks", {'grid.linestyle': '--'})
    plt.locator_params(axis='x', nbins=11)
    ax.set_xlabel('Time (s)', fontsize=20)
    ax.set_ylabel('Congestion window (pkts.)', fontsize=20)

    plt.yticks(fontsize=18)
    plt.xticks(fontsize=18)

    plt.grid(True, which='major', lw=0.65, ls='--', dashes=(3, 7), zorder=70)
    #plt.legend(fontsize=20, loc='best')

    ax.set_ylim(bottom=0)

    # Hide the right and top spines
    ax.spines['right'].set_visible(False)
    ax.spines['top'].set_visible(False)

    # Only show ticks on the left and bottom spines
    ax.yaxis.set_ticks_position('left')
    ax.xaxis.set_ticks_position('bottom')

    # ax.get_legend().remove()
    plt.margins(x=0.02)
    plt.tight_layout(pad=0.4, w_pad=0.5, h_pad=1.0)
    plt.savefig(pdf_dir + '/' + filename + '.pdf',
                format='pdf',
                dpi=1200,
                bbox_inches='tight',
                pad_inches=0.025)


if __name__ == '__main__':
    fname_arg = sys.argv[1]
    nbits_arg = sys.argv[2]
    rate_arg = sys.argv[3]
    run_arg = sys.argv[4]
    plot_cwnd_stats(pdf_dir='.',
                    fname=fname_arg,
                    nbits=nbits_arg,
                    rate=rate_arg,
                    run=run_arg)
