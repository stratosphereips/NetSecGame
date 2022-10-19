import matplotlib.pyplot as plt
import numpy as np
import pickle

with open("learning_comparison10K.pickle","rb") as f:
       data  = pickle.load(f)
wins = data["returns"]
means = wins.mean(axis=(2,3))
std = wins.std(axis=(2,3))
print(means.shape)

# # make data
# #np.random.seed(1)
x = np.linspace(0,40,40)
# # plot
fig, ax = plt.subplots()
x_new = np.linspace(0,40,10001)
print(x_new.shape, x.shape, means.shape)

m_0interp = np.interp(x_new, x, means[0])
s_0interp = np.interp(x_new, x, std[0])
m_1interp = np.interp(x_new, x, means[1])
s_1interp = np.interp(x_new, x, std[1])
m_2interp = np.interp(x_new, x, means[2])
s_2interp = np.interp(x_new, x, std[2])

# # plot
fig, ax = plt.subplots()
ax.fill_between(np.linspace(0,10000,10001), m_0interp-s_0interp, m_0interp+s_0interp, alpha=.1, linewidth=0, color="r")
ax.fill_between(np.linspace(0,10000,10001), m_2interp-s_2interp, m_2interp+s_2interp, alpha=.1, linewidth=0, color="b")
ax.fill_between(np.linspace(0,10000,10001), m_1interp-s_1interp, m_1interp+s_1interp, alpha=.1, linewidth=0, color="g")
#ax.plot(means[0], linewidth=1.25,color="r", label="Naive")
ax.plot(m_1interp, linewidth=1.25,color="g", label="Q-learning")
ax.plot(m_2interp, linewidth=1.25,color="b", label="Double Q-learning")
ax.plot(m_0interp, linewidth=1.25,color="r", label="Naive Q-learning")
# # ax.set(xlim=(0, 50),
# #        ylim=(0, 10))
#plt.legend(loc="upper left")
plt.legend(loc="lower right")
plt.title("Agent Mean Return Comparison", fontweight="bold")
plt.xlabel('Iteration')
plt.ylabel('Mean Return')
fig.tight_layout()
plt.savefig("test.png", dpi=600)
