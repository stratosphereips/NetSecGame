import matplotlib.pyplot as plt
import numpy as np
import pickle
import sys
from scipy.interpolate import make_interp_spline

with open(sys.argv[1],"rb") as f:
       data  = pickle.load(f)
wins = data["returns"]
print(wins.shape)
means = np.mean(wins,axis=(2))
std = wins.std(axis=(2))/1.5
#print(np.mean(wins[:,0, :, :], axis=(2)))


size = int(data["parameters"]["training_episodes"]/data["parameters"]["eval_each"]) +1
x = np.linspace(0,size, size)
# # # plot
fig, ax = plt.subplots()
x_new = np.linspace(0, size, data["parameters"]["training_episodes"] +1)
print(x_new.shape, x.shape, means[0].shape)

m_0interp = np.convolve(np.interp(x_new, x, means[0]),np.ones(100)/100, mode="valid")[:17500]
s_0interp = np.interp(x_new, x, std[0])[:17500]
m_1interp =  np.convolve(np.interp(x_new, x, means[1]), np.ones(100)/100,  mode="valid")[:17500]
s_1interp = np.interp(x_new, x, std[1])[:17500]
m_2interp = np.convolve(np.interp(x_new, x, means[2]),np.ones(100)/100, mode="valid")[:17500]
s_2interp = np.interp(x_new, x, std[2])[:17500]

# m_0interp = means[0]
# s_0interp = std[0]
# m_1interp = means[1]
# s_1interp = std[1]
# m_2interp = means[2]
# s_2interp = std[2]
# # plot
# fig, ax = plt.subplots()
ax.fill_between(np.linspace(0, s_2interp.shape[-1], s_2interp.shape[-1]), m_0interp-s_0interp, m_0interp+s_0interp, alpha=.1, linewidth=0, color="r")
ax.fill_between(np.linspace(0, s_2interp.shape[-1], s_2interp.shape[-1]), m_1interp-s_1interp, m_1interp+s_1interp, alpha=.1, linewidth=0, color="g")
ax.fill_between(np.linspace(0, s_2interp.shape[-1], s_2interp.shape[-1]), m_2interp-s_2interp, m_2interp+s_2interp, alpha=.1, linewidth=0, color="b")
# ax.fill_between(np.linspace(0,101 +1), m_0interp-s_0interp, m_0interp+s_0interp, alpha=.1, linewidth=0, color="r")
# ax.fill_between(np.linspace(0,101 +1), m_2interp-s_2interp, m_2interp+s_2interp, alpha=.1, linewidth=0, color="b")
# ax.fill_between(np.linspace(0,101 +1), m_1interp-s_1interp, m_1interp+s_1interp, alpha=.1, linewidth=0, color="g")

#ax.plot(means[0], linewidth=1.25,color="r", label="Naive")
ax.plot(m_0interp, linewidth=1.25,color="r", label="Naive Q-learning")
ax.plot(m_1interp, linewidth=1.25,color="g", label="Q-learning")
ax.plot(m_2interp, linewidth=1.25,color="b", label="Double Q-learning")
# # ax.set(xlim=(0, 50),
# #        ylim=(0, 10))
#plt.legend(loc="upper left")
plt.legend(loc="lower right")
plt.title("Agent Mean Return Comparison", fontweight="bold")
plt.xlabel('Training episodes')
plt.ylabel('Mean Return')
fig.tight_layout()
plt.savefig("returns.png", dpi=1000)
